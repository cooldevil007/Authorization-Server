var express = require("express");
var url = require("url");
var bodyParser = require("body-parser");
var randomstring = require("randomstring");
var cons = require("consolidate");
var nosql = require("nosql").load("database.nosql");
var querystring = require("querystring");
var _ = require("underscore");
const { Console } = require("console");
_.string = require("underscore.string");

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "authorizationServer");
app.set("json spaces", 4);

var authServer = {
  authorizationEndpoint: "http://localhost:4005/authorize",
  tokenEndpoint: "http://localhost:4005/token",
};

var clients = [
  {
    client_id: "anand-client-007",
    client_secret: "anand-client-secret-007",
  },
];

var code = {};
var requests = {};
var redirect_url = {};
var state_data = {};
var client_data = {};

/*
app.get('/', function(req, res) {
	return res.render('index', {clients: clients, authServer: authServer});
});
*/

app.get("/authorize", (req, res) => {
    // redirect data from request.
    redirect_url = req.query.redirect_uri;
    // Client Data from request
    client_data = req.query.client_id;

    console.log("Redirect URL is %s", redirect_url);

    // scope data from request
    scope_data = req.query.scope ? req.query.scope.split(" ") : undefined;
    console.log("Inside authorize function");
    // State Data from Request
    state_data = req.query.state;

    console.log("Client ID from Alexa app is %s", client_data);
    console.log("State Value passed from Alexa app is %s", state_data);
    console.log("Final point here");
    //return res.render('approve', {client: client, reqid: reqid , scope: rscope});

    return res.render("newIndex.html");
});

app.post("/approve", (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  nosql.insert({ username: username, password: password });

  return res.render("approve.html");
});

app.post("/authcode", (req, res) => {
  /*
    if(!query){
        return res.render('error', {error: 'No matching authorization server'});
    }
*/
  if (req.body.approve) {
    code = randomstring.generate(12);

    var urlParsed = buildUrl(redirect_url, { code: code, state: state_data });

    console.log(urlParsed);

    return res.redirect(urlParsed);

  } else {
    var urlParsed = buildUrl(redirect_url, { error: "access_denied" });
    return res.redirect(urlParsed);
  }
});

app.post("/token", (req, res) => {
  if (req.body.grant_type == "authorization_code") {
    var access_token = randomstring.generate();
    var refresh_token = randomstring.generate();

    nosql.insert({ access_token: access_token });

    nosql.insert({ refresh_token: refresh_token });

    console.log("Issuing access token %s", access_token);

    var token_response = {
      access_token: access_token,
      token_type: "Bearer",
      refresh_token: refresh_token,
      expires_in: "3600"
    };

    res.status(200).json(token_response);
    console.log("Issued tokens for code %s", req.body.code);

    return;
  } else if (req.body.grant_type == "refresh_token") {
    var access_token = randomstring.generate();
    nosql.insert({ access_token: access_token, client_id: client_data });
    var token_response = {
      access_token: access_token,
      token_type: "Bearer",
      refresh_token: token.refresh_token,
      expires_in: "3600"
    };
    res.status(200).json(token_response);
    return;
  } else {
    console.log("Unknown grant type %s", req.body.grant_type);
    res.status(400).json({ error: "unsupported_grant_type" });
  }
});

var buildUrl = (base, options) => {
  var newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  _.each(options, (value, key, list) => {
    newUrl.query[key] = value;
  });
  return url.format(newUrl);
};

app.use("/", express.static("files/authorizationServer"));

var server = app.listen(4005, "localhost", function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log("Authorization server is listening at http://%s:%s", host, port);
});
