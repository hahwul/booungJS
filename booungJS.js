// BooungJS v1.0
// This script is security analysis javascript code
// Load a script !
// [GIT] : https://github.com/hahwul/booungJS
// [AUTHOR] : HAHWUL(www.hahwul.com)

// $.getScript("http://hahwul.com/1.js");
// document.write("<script src='http://hahwul.com/1.js'></script>");

var Base64 = {
	// private property
	_keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
	// public method for encoding
	encode : function (input) {
		var output = "";
		var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
		var i = 0;
		while (i < input.length) {
		  chr1 = input.charCodeAt(i++);
		  chr2 = input.charCodeAt(i++);
		  chr3 = input.charCodeAt(i++);
		  enc1 = chr1 >> 2;
		  enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
		  enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
		  enc4 = chr3 & 63;
		  if (isNaN(chr2)) {
			  enc3 = enc4 = 64;
		  } else if (isNaN(chr3)) {
			  enc4 = 64;
		  }
		  output = output +
			  this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
			  this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
		}
		return output;
	},
	// public method for decoding
	decode : function (input)
	{
	    var output = "";
	    var chr1, chr2, chr3;
	    var enc1, enc2, enc3, enc4;
	    var i = 0;
	    input = input.replace(/[^A-Za-z0-9+/=]/g, "");
	    while (i < input.length)
	    {
	        enc1 = this._keyStr.indexOf(input.charAt(i++));
	        enc2 = this._keyStr.indexOf(input.charAt(i++));
	        enc3 = this._keyStr.indexOf(input.charAt(i++));
	        enc4 = this._keyStr.indexOf(input.charAt(i++));
	        chr1 = (enc1 << 2) | (enc2 >> 4);
	        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
	        chr3 = ((enc3 & 3) << 6) | enc4;
	        output = output + String.fromCharCode(chr1);
	        if (enc3 != 64) {
	            output = output + String.fromCharCode(chr2);
	        }
	        if (enc4 != 64) {
	            output = output + String.fromCharCode(chr3);
	        }
	    }
	    return output;
	}
}

function booungJS()
{
	// init..
	//
	this.all_list = document.all;
	this.all_count = document.all.length;
	this.scr_list = document.scripts;
	this.scr_count = document.scripts.length;	
	this.scr_report = new Array();
	// ------
	this.banner();
	this.scr_buf = [];
	this.all_buf = [];
	var i=0;
	while(i<this.scr_count)
	{
		this.scr_buf.push(this.scr_list[i].text);
		if(this.scr_list[i].src != "")
		{
		//console.log("NOT NULL"+i);	
		}	
		i++;
	}
	i=0
	while(i<this.all_count)
	{
		this.all_buf.push(this.all_list[i].text);
		i++;
	}
	console.log("Loaded the HTML/JS data in page using booungJS. >> ["+this.all_count+" HTML object / "+this.scr_count+" JS object] on DOM Area");
	this.help();
}
booungJS.prototype.banner = function banner()
	{
		console.log("  , _ ,   ____     By HAHWUL[www.hahwul.com]       _ ____  \n ( o o ) | __ )  ___   ___  _   _ _ __   __ _    | / ___| \n/'` ' `'\\|  _ \\ / _ \\ / _ \\| | | | '_ \\ / _` |_  | \\___ \\ \n|'''''''|| |_) | (_) | (_) | |_| | | | | (_| | |_| |___) |\n|\\\\'''//||____/ \\___/ \\___/ \\__,_|_| |_|\\__, |\\___/|____/ \n   '''                                  |___/ \nVulnerability analysis to javascript using javascript and web debugger.");
	}
booungJS.prototype.help = function help()
	{
		console.log('booungJS Command line\n - booung.anlaysis()                # analysis HTML/Javascript code\n - booung.search("document.write")  # find text\n - booung.base64("ABCD")            # encode&decode base64\n - booung.help()                    # show help\n - booung.banner()                  # load banner ');
		
		/*

		 - booung.anlaysis()                # analysis javascript code
		 - booung.search("document.write")  # find text
		 - booung.base64("ABCD")            # encode&decode base64
		 - booung.help()                    # show help
		 - booung.banner()                  # load banner 
		 
		 */ 
	}
booungJS.prototype.base64 = function base64(data) // Insert to report data function
	{  
		return "\nEncode: "+Base64.encode(data)+"\nDecode: "+Base64.decode(data)+"\n";
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
			console.log("["+this.scr_report[i][0]+"]["+this.scr_report[i][1]+"]:"+this.scr_report[i][2]);
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
		var md5_pattern = new RegExp("/^[a-f0-9]{32}$/","i");
		console.log("-script analysis")
		var i = 0;
		while(i<this.scr_count)
		{
			var result = this.scr_buf[i].indexOf("localStorage");
			if(result != -1)
			{
				this.rpush("INF","ANALYSIS_MODULE","[localStorage] : "+result+" line in"+this.scr_list[i].id+".");
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");
			}
			result = this.scr_buf[i].indexOf("sessionStorage");
			if(result != -1)
			{
				this.rpush("INF","ANALYSIS_MODULE","[sessionStorage] : "+result+" line in"+this.scr_list[i].id+".");
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");
			}
			result = this.scr_buf[i].indexOf("document.write(");
			if(result != -1)
			{
				this.rpush("INF","ANALYSIS_MODULE","[dom write] : "+result+" line in"+this.scr_list[i].id+".");
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");
			}
			result = this.scr_buf[i].indexOf("eval(");
			if(result != -1)
			{
				this.rpush("INF","ANALYSIS_MODULE","[eval function] : "+result+" line in"+this.scr_list[i].id+".");
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");
			}
			i++;
		}
		i=0;
		while(i<this.all_count)
		{
			var result = this.all_buf[i].search(md5_pattern);
			if(result != -1)
			{
				this.rpush("INF","HTML_MODULE","[md5] : "+result+" line in"+this.scr_list[i].id+".");
				console.info(" >> "+result+" line in"+this.scr_list[i].id+".");	
			}
			i++;
		}
		console.log("Complate!");
	};

var booung = new booungJS();
	
