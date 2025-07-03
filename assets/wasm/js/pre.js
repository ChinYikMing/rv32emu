Module['noInitialRun'] = true;
let init = false;
let cbuffer_ptr;
let term;
let is_cbuffer_avail = false;
Module['onRuntimeInitialized'] = function(target_elf) {
	if(!init){
		init = true;
	cbuffer_ptr = Module._get_input_buffer();

    term = new Terminal({
        cols: 120,
        rows: 25,
    });
    term.open(document.getElementById('terminal'));
    term.write('$ ');
    term.scrollToBottom();

    let currLine = "";

    term.onKey(({ key, domEvent }) => {
        const code = key.charCodeAt(0);

        Module._set_input_buffer_in(true);
	Module.HEAPU8[cbuffer_ptr] = code;
        is_cbuffer_avail = true;
	//console.log(code);

        term.scrollToBottom();
    });



	}


    if(target_elf === undefined){
      console.warn("target elf executable is undefined");
      return;
    }

    if(target_elf.startsWith("-k")){
        callMain(target_elf.split(" "));
    } else {
        callMain([target_elf]);
    }
};
