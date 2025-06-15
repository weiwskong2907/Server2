<?php
$file = __DIR__ . '/../includes/functions.php';
$content = file_get_contents($file);
$lines = explode("\n", $content);

$braces = [];
$errors = [];

foreach ($lines as $number => $line) {
    $lineNumber = $number + 1;
    $matches = [];
    preg_match_all('/[{}]/', $line, $matches);
    
    foreach ($matches[0] as $brace) {
        if ($brace === '{') {
            array_push($braces, $lineNumber);
        } else if ($brace === '}') {
            if (empty($braces)) {
                $errors[] = "Extra closing brace on line $lineNumber";
            } else {
                array_pop($braces);
            }
        }
    }
}

if (!empty($braces)) {
    foreach ($braces as $line) {
        $errors[] = "Unclosed brace from line $line";
    }
}

if (!empty($errors)) {
    echo "Found brace mismatches:\n";
    foreach ($errors as $error) {
        echo "- $error\n";
    }
} else {
    echo "No brace mismatches found.\n";
}