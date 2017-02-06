//BooungJS
// This script is security analysis javascript code
// Load a script !
// $.getScript("http://hahwul.com/1.js");


//document.scripts[40].innerText.length
//document.scripts.length

function booungJS()
{
	// init..
	this.scr_list = document.scripts;
	this.scr_count = document.scripts.length;	
	// ------
	 
	this.scr_buf = [];
	var i=0;
	while(i<this.scr_count)
	{
		this.scr_buf = this.scr_list[i];
		i++;
	}
 
}
booungJS.prototype.search = function search(searchq)
	{
		var i = 0;
		console.log("[INF] Searching.. ["+searchq+"]");
		while(i<this.scr_count)
		{
			buf = this.scr_list[i].innerText;
			console.log(this.scr_list[i].text);
			console.log(i);
			i++;
		}
	};

var booung = new booungJS();
	
