// BooungJS v1.0
// This script is security analysis javascript code
// Load a script !
// [GIT] : https://github.com/hahwul/booungJS
// [AUTHOR] : HAHWUL(www.hahwul.com)

// $.getScript("http://hahwul.com/1.js");

//document.scripts[40].innerText.length
//document.scripts.length

function booungJS()
{
	// init..
	this.scr_list = document.scripts;
	this.scr_count = document.scripts.length;	
	this.scr_report = new Array();
	// ------
	this.banner();
	this.scr_buf = [];
	var i=0;
	while(i<this.scr_count)
	{
		this.scr_buf.push(this.scr_list[i].text);
		i++;
	}
	console.log("Loaded the Javascript data associated with the page using booungJS. >> "+this.scr_count+" script object\n[Please show me help page] #> booungJS.help())");
}
booungJS.prototype.banner = function banner()
	{
		console.log("  , _ ,   ____     By HAHWUL[www.hahwul.com]       _ ____  \n ( o o ) | __ )  ___   ___  _   _ _ __   __ _    | / ___| \n/'` ' `'\\|  _ \\ / _ \\ / _ \\| | | | '_ \\ / _` |_  | \\___ \\ \n|'''''''|| |_) | (_) | (_) | |_| | | | | (_| | |_| |___) |\n|\\\\'''//||____/ \\___/ \\___/ \\__,_|_| |_|\\__, |\\___/|____/ \n   '''                                  |___/ \nVulnerability analysis to javascript using javascript and web debugger.");
	}
booungJS.prototype.help = function help()
	{
		console.log("new object booungJS");
		console.log(" > var boo = new booungJS()");
		console.log("search text");
		console.log(" > booung.search('your text')");
		console.log("vulnerability&security analysis");
		console.log(" > booung.analysis()");
		console.log("");
		console.log("");
	}
booungJS.prototype.rpush = function rpush(type,category,data) // Insert to report data function
	{  // this.rpush("INF","SEARCH_MODULE","["+searchq+"] : "+result+" line in"+this.scr_list[i].id+".");
		var count = this.scr_report.length;
		this.scr_report.push(new Array());
		this.scr_report[count].push(type,category,data);
	}
booungJS.prototype.report = function report() // Insert to report data function
	{  // 
		console.log("REPORT");
		var buf = "booungJS > Vulnerability&Security risk Analysis report"
		for(var i=0;i<this.scr_report.length;i++)
		{
			console.log(this.scr_report[i][0]);
			console.log(this.scr_report[i][1]);
			console.log(this.scr_report[i][2]);
		}
	}
booungJS.prototype.search = function search(searchq)
	{
		var i = 0;
		console.log("Searching.. ["+searchq+"]");
		while(i<this.scr_count)
		{
			var result = this.scr_buf[i].indexOf(searchq);
			if(result != -1)
			{
				this.rpush("INF","SEARCH_MODULE","["+searchq+"] : "+result+" line in"+this.scr_list[i].id+".");
				console.info(" >> Found ["+searchq+"] "+result+" line in"+this.scr_list[i].id+".");
			}
			i++;
		}
		console.log("Complate!");
	};
booungJS.prototype.analysis = function analysis()
	{
		var i = 0;
		
		while(i<this.scr_count)
		{
			var result = this.scr_buf[i].indexOf("localStorage");
			if(result != -1)
			{
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");
			}
			result = this.scr_buf[i].indexOf("sessionStorage");
			if(result != -1)
			{
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");
			}
			result = this.scr_buf[i].indexOf("document.write(");
			if(result != -1)
			{
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");
			}
			result = this.scr_buf[i].indexOf("eval(");
			if(result != -1)
			{
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");
			}
			i++;
		}
		console.log("Complate!");
	};

var booung = new booungJS();
	
