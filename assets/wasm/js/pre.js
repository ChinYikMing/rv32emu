Module["noInitialRun"] = true;
let init = false;
let cbuffer_ptr;
let term;
let sequence;

Module["onRuntimeInitialized"] = function (target_elf) {
  if (!init) {
    init = true;
    cbuffer_ptr = Module._get_input_buffer();
    cbuffer_cap = Module._get_input_buffer_cap();

    term = new Terminal({
      cols: 120,
      rows: 25,
    });
    term.open(document.getElementById("terminal"));

    term.onKey(({ key, domEvent }) => {
      const code = key.charCodeAt(0);

      switch (domEvent.key) {
        case "ArrowUp":
          // ESC [ A → "\x1B[A"
          sequence = "\x1B[A";
          break;
        case "ArrowDown":
          // ESC [ B → "\x1B[B"
          sequence = "\x1B[B";
          break;
        case "ArrowRight":
          // ESC [ C → "\x1B[C"
          sequence = "\x1B[C";
          break;
        case "ArrowLeft":
          // ESC [ D → "\x1B[D"
          sequence = "\x1B[D";
          break;
        // TODO: support more keys?
        default:
          sequence = key;
          break;
      }

      let heap = new Uint8Array(
        Module.HEAPU8.buffer,
        cbuffer_ptr,
        sequence.length,
      );

      for (let i = 0; i < sequence.length && i < cbuffer_cap; i++) {
        heap[i] = sequence.charCodeAt(i);
      }
      for (let i = sequence.length; i < cbuffer_cap; i++) {
        heap[i] = 0; // Zero-fill
      }

      Module._set_escape_char_size(sequence.length);
      Module._set_input_buffer_in(true);

      term.scrollToBottom();
    });
  }

  if (target_elf === undefined) {
    console.warn("target elf executable is undefined");
    return;
  }

  if (target_elf.startsWith("-k")) {
    callMain(target_elf.split(" "));
  } else {
    callMain([target_elf]);
  }
};
