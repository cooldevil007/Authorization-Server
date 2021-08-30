var express = require('express');
var url = require('url');
var bodyParser = require('body-parser');
var randomstring = require('randomstring');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var _ = require('underscore');
const { Console } = require('console');
_.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'authorizationServer');
app.set('json spaces', 4);

var authServer = {
	authorizationEndpoint: 'http://localhost:4005/authorize',
	tokenEndpoint: 'http://localhost:4005/token'
};

var clients = [
	{
		"client_id": "anand-client-007",
		"client_secret": "anand-client-secret-007",
        "redirect_uris": ["https://pitangui.amazon.com/api/skill/link/M2AAAAAAAAAAAA"]
	}
];


var code = {};
var requests = {};
var redirect_url = {};
var state_data= {};

var getClient = (clientId) => {
    return _.find(clients, (client) => {
        return client.client_id == clientId;
    });
};

/*
app.get('/', function(req, res) {
	return res.render('index', {clients: clients, authServer: authServer});
});
*/

app.get("/authorize", (req, res) => {
    var client = getClient(req.query.client_id);
    redirect_url = req.query.redirect_uri;

    if (!client) {
        console.log('Unknown Client %s', req.query.client_id);
        return res.render('error', {error: 'Unknown Client'});

    } else if (!_.contains(client.redirect_uris, req.query.redirect_uri)) {
        console.log('Mismatched redirect URI, expected %s got %s', client.redirect_uris, req.query.redirect_uri);
        return res.render('error', {error: 'Invalid redirect URI'});
        
    } else {
        var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (_.difference(rscope, cscope).length > 0) {
			// client asked for a scope it couldn't have
			var urlParsed = url.parse(req.query.redirect_uri);
			delete urlParsed.search; // this is a weird behavior of the URL library
			urlParsed.query = urlParsed.query || {};
			urlParsed.query.error = 'invalid_scope';
			res.redirect(url.format(urlParsed));
			return;
        }

        console.log("Inside authorize function and about to generate req ID");
        var reqid = randomstring.generate(8);
        console.log("Req ID is %s", reqid);
        requests[reqid] = req.query;
        state_data = req.query.state;
        console.log("State Value passed from Alexa app is %s", state_data);
        console.log("Final point here");
        //return res.render('approve', {client: client, reqid: reqid , scope: rscope});

        return res.render('newIndex', {client: client, reqid: reqid , scope: rscope});
    }
});

app.post("/credentials", (req,res)=> {
    var username = req.body.username;
    var password = req.body.password;

    var reqid_data = req.body.reqid;
    var client_data = req.body.client;
    var scope_data = req.body.scope;

    nosql.insert({username: username, password: password});

    return res.render("approve", {client: client_data, reqid: reqid_data , scope: scope_data});
    
});

app.post("/approve", (req, res)=> {
    var reqid = req.body.reqid;

    var query = requests[reqid];
    delete requests[reqid];

    if(!query){
        return res.render('error', {error: 'No matching authorization server'});
    }

    if(req.body.approve){
        if(query.response_type == 'code'){
            var code = randomstring.generate(8);

            codes[code] = {request: query};

            var urlParsed = buildUrl(query.redirect_uri, {code: code, state: state_data});

            return res.redirect(urlParsed);
        } else {
            var urlParsed = buildUrl(query.redirect_uri, {error: "Unsupported_response_type"});

            return res.redirect(urlParsed);
        }
    }else {
        var urlParsed = buildUrl(query.redirect_uri, {error: "access_denied"});
        return res.redirect(urlParsed);
    }
});

app.post("/token", (req, res) => {
    var auth = req.header['authorization'];

    if(auth) {
        var clientCredentials = decodeClientCredentials(auth);
        var clientId = clientCredentials.id;
        var clientSecret = clientCredentials.secret;
    }

    if(req.body.client_id){
        if(clientId){
            console.log("Client attempted to authenticate with multiple methods");
            return res.status(401).json({error: "invalid_client"});
            
        }

        var clientId = req.body.client_id;
        var clientSecret = req.body.client_secret;
    }

    var client = getClient(clientId);

    if(!client){
        console.log("Unknown client %s", clientId);
        return res.status(401).json({error: "invalid_client"});
    }

    if(client.client_secret != clientSecret){
        console.log("Mismatched client secret, expected %s got %s", client.client_secret, clientSecret);
        return res.status(401).json({error: "invalid_client"});

    }

    if(req.body.grant_type == 'authorization_code'){
        var code = codes[req.body.code];

        if(code){
            delete codes[req.body.code];

            if(code.request.client_id == clientId){
                var access_token = randomstring.generate();
                var refresh_token = randomstring.generate();

                nosql.insert({access_token: access_token, client_id: clientId});

                nosql.insert({refresh_token: refresh_token, client_id: clientId});

                console.log('Issuing access token %s', access_token);

                var token_response = {access_token: access_token, token_type: 'Bearer', refresh_token: refresh_token };

                res.status(200).json(token_response);
                console.log("Issued tokens for code %s", req.body.code);

                return;

            } else {
                console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
                res.status(400).json({error: 'invalid_grant'});
                return;
            }
        }else {
            console.log('Unknown code, %s', req.body.code);
            res.status(400).json({error: 'invalid_grant'});
            return;
        }
    }else if (req.body.grant_type == 'refresh_token'){
        nosql.one().make(function(builder){
            builder.where('refresh_token', req.body.refresh_token);
            builder.callback(function(err , token){
                if(token){
                    console.log("We found a matching refresh token: %s", req.body.refresh_token);
                    if(token.client_id != clientId){
                        nosql.remove().make(function(builder){
                            builder.where('refresh_token', req.body.refresh_token);
                        });
                        res.status(400).json({error: 'invalid_grant'});
                        return;
                    }

                    var access_token = randomstring.generate();
                    nosql.insert({access_token: access_token, client_id: clientId});
                    var token_response = {access_token: access_token, token_type: 'Bearer', refresh_token: token.refresh_token};
                    res.status(200).json(token_response);
                    return;
                }else {
                    console.log('No matching token was found.');
                    res.status(400).json({error: 'invalid_grant'});
                    return;
                };
            })
        });
    }else {
        console.log("Unknown grant type %s", req.body.grant_type);
        res.status(400).json({error: 'unsupported_grant_type'});
    }
});

var buildUrl = (base, options, hash)=> {
    var newUrl = url.parse(base, true);
    delete newUrl.search;
    if(!newUrl.query){
        newUrl.query= {};
    }
    _.each(options, (value, key, list)=> {
        newUrl.query[key] = value;
    });
    if(hash){
        newUrl.hash = hash;
    }
    return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

var getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

app.use('/', express.static('files/authorizationServer'));

var server = app.listen(4005, 'localhost', function(){
    var host = server.address().address;
    var port = server.address().port;

    console.log('Authorization server is listening at http://%s:%s', host, port);
});
