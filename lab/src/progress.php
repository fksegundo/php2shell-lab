<?php
// Consumer endpoint: only starts the session normally.
// The early consumer is the upload-progress handler, which runs before this.
session_start();
echo "OK\n";
