<?php

function customErrorHandler($errno, $errstr, $errfile, $errline) {
    $errorType = match ($errno) {
        E_ERROR => 'Fatal Error',
        E_WARNING => 'Warning',
        E_PARSE => 'Parse Error',
        E_NOTICE => 'Notice',
        E_CORE_ERROR => 'Core Error',
        E_CORE_WARNING => 'Core Warning',
        E_COMPILE_ERROR => 'Compile Error',
        E_COMPILE_WARNING => 'Compile Warning',
        E_USER_ERROR => 'User Error',
        E_USER_WARNING => 'User Warning',
        E_USER_NOTICE => 'User Notice',
        E_STRICT => 'Strict Notice',
        E_RECOVERABLE_ERROR => 'Recoverable Error',
        E_DEPRECATED => 'Deprecated',
        E_USER_DEPRECATED => 'User Deprecated',
        default => 'Unknown Error'
    };

    $message = sprintf(
        "[%s] %s: %s in %s on line %d",
        date('Y-m-d H:i:s'),
        $errorType,
        $errstr,
        $errfile,
        $errline
    );

    error_log($message);

    if (DEBUG_MODE && !in_array($errno, [E_NOTICE, E_USER_NOTICE, E_DEPRECATED, E_USER_DEPRECATED])) {
        echo "<pre>$message</pre>";
    }

    return true;
}

set_error_handler('customErrorHandler');

function shutdownHandler() {
    $error = error_get_last();
    if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        customErrorHandler(
            $error['type'],
            $error['message'],
            $error['file'],
            $error['line']
        );
    }
}

register_shutdown_function('shutdownHandler');