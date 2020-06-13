// Just some parameters
var express=require("express");
var mysql = require('mysql');
var bodyParser=require("body-parser");
var path=require("path");
const {TwingEnvironment, TwingLoaderFilesystem} = require('twing');
let loader = new TwingLoaderFilesystem('./templates');
let twing = new TwingEnvironment(loader);
var app=express();
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname,"static")));

var con = mysql.createConnection({
  host: "localhost",
  user: #### REDACTED ####,
  password: #### REDACTED ####,
  database: #### REDACTED ####
});

//The juicy part

app.get("/",function(req,res){
var msg="Results Of search here";
twing.render('index.twig',{'msg':msg}).then((output) => {
        res.end(output);
	});
});
app.post("/",function(req,res){
        var input=req.body.search+"%" ;
        if (input.search(/ |"|union|select|;|1/)=== -1){
        con.query('SELECT * FROM best_anime WHERE anime_name LIKE'.concat(" '",input).concat("","'"), (err,rows) => {
                if(err) {
                        twing.render('index.twig',{'msg':err.message}).then((output) => {
                                res.end(output);
                                });
                        }
                else {        
                var msg="Got "+rows.length+" results:";
                twing.render('index.twig',{'msg':msg,'res':rows}).then((output) => {
                        res.end(output);
                        });

        }
              });
        }
        else{
                var msg="Hey little script kiddie stay away of my website";
                twing.render('index.twig',{'msg':msg}).then((output) => {
                        res.end(output);
                        });

        }
              
});
app.listen(5555);
console.log("Listening on 5555")
