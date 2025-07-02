Module['noInitialRun'] = true;
Module['onRuntimeInitialized'] = function(target_elf) {
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
