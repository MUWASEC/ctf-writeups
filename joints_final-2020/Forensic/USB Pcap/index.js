document.onkeydown = checkKey;
var flag = new Array('')
for (var i=0;i<26;i++){
	flag.push(' ')
}
ind=0;

function checkKey(e) {
    e = e || window.event;

    k = document.getElementsByClassName("selected")[0];
    if (e.keyCode == '38') {
        // up arrow
        row = parseInt(k.id.split('-')[0]);
        col = parseInt(k.id.split('-')[1]);

        // if top, do nothing
        if(row == 1) return;
        k.classList.remove('selected');
        row -= 1;
        col = col.toString().length <2 ? '0'+col:col;
        k = document.getElementById(row.toString()+'-'+col)
        k.classList.add('selected')
    }
    else if (e.keyCode == '40') {
        // down arrow
        row = parseInt(k.id.split('-')[0]);
        col = parseInt(k.id.split('-')[1]);

        // if bottom, do nothing
        if(row == 3) return;
        k.classList.remove('selected');
        row += 1;
        if (row==3 && col==26) col = 25;
        col = col.toString().length <2 ? '0'+col:col;
        k = document.getElementById(row.toString()+'-'+col)
        k.classList.add('selected')
    }
    else if (e.keyCode == '37') {
       // left arrow
       row = parseInt(k.id.split('-')[0]);
       col = parseInt(k.id.split('-')[1]);

       // if left, do nothing
       if(col == 1) return;
       k.classList.remove('selected');
       col -= 1;
       col = col.toString().length <2 ? '0'+col:col;
       k = document.getElementById(row.toString()+'-'+col)
       k.classList.add('selected')
    }
    else if (e.keyCode == '39') {
       // right arrow
       row = parseInt(k.id.split('-')[0]);
       col = parseInt(k.id.split('-')[1]);

       // if right, do nothing
       if(col == 26 || (row==3 && col == 25)) return;
       k.classList.remove('selected');
       col += 1;
       col = col.toString().length <2 ? '0'+col:col;
       k = document.getElementById(row.toString()+'-'+col)
       k.classList.add('selected')
    }
    else if(e.keyCode == '13'){
    	val = k.innerText;
    	if(val != 'Del' && ind < 26){
    		flag[ind++] = val;
    		col = (ind).toString().length < 2? '0'+(ind).toString(): (ind).toString();
			f = document.getElementById('f-'+col);
			f.classList.add('filled');
    		f.innerText = val;
    	} else if(ind > 0 && val == 'Del'){
    		// del
    		flag[--ind] = ' ';
    		col = (ind+1).toString().length < 2? '0'+(ind+1).toString(): (ind+1).toString();
			f = document.getElementById('f-'+col);
			f.classList.remove('filled');
			f.innerText = ' ';
    	}
    }
}