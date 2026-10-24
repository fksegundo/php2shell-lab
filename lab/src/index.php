<?php
// The vulnerable page. It does not use sessions or uploads itself:
// PHP's session.upload_progress handler runs before this code.
echo "OK\n";
