Module['noInitialRun'] = true;
Module['onRuntimeInitialized'] = function(target_elf) {
    if(target_elf === undefined){
      console.warn("target elf executable is undefined");
      return;
    }

    //callMain([target_elf]);
    arr = [];
    arr.push('-k');
    arr.push('Image');
    arr.push('-i');
    arr.push('rootfs.cpio');
    arr.push('-b');
    arr.push('minimal.dtb');
    console.log(arr)
    callMain(arr);
    //callMain(['-k', 'Image', '-i', 'rootfs.cpio', '-b', 'minimal.dtb']);
};
