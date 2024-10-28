<?php

function getScriptData_listingArray_childTheme($html) {
    $scripts = [];
    $pattern = '/<script\s+src=["\']([^"\']+)["\']\s*(?:id=["\']([^"\']+)["\'])?[^>]*><\/script>/i';
    preg_match_all($pattern, $html, $matches, PREG_SET_ORDER);

    // Loop through the matches to build the array
    foreach ($matches as $match) {
        $src = isset($match[1]) ? $match[1] : '';
        $id = isset($match[2]) ? $match[2] : '';
        $scripts[] = ['id' => $id, 'src' => $src];
    }

    return $scripts;
}


function add_meta_tag_after_head__childTheme($html, $metaTag) {
    $pattern = '/<head\b([^>]*)>/i';
    $replacement = '<head$1>' . PHP_EOL . '    ' . $metaTag;
    $updatedHtml = preg_replace($pattern, $replacement, $html);
    return $updatedHtml;
}

function getStylesheetData_listingArray_childTheme($html) {
    $stylesheets = [];
    // Pattern to match <link> tags with href and optional id attributes
    // $pattern = '/<link\s+rel=["\']stylesheet["\']\s+href=["\']([^"\']+)["\']\s*(?:id=["\']([^"\']+)["\'])?[^>]*>/i';
    $pattern = '/<link\s+[^>]*href=["\']([^"\']*\.css)["\'][^>]*>/i';
    preg_match_all($pattern, $html, $matches, PREG_SET_ORDER);

    // Loop through the matches to build the array
    foreach ($matches as $match) {
        // $id = isset($match[1]) ? $match[1] : '';

        // $href = isset($match[2]) ? $match[2] : '';
        // $stylesheets[] = ['id' => $id, 'href' => $href];
    }
    
    print_r($matches);
    return $stylesheets;
}



// Example HTML
$html = '
<html>
<head>
  <title>Example Page</title>
  <script src="https://example.com/script1.js"></script>
  <script src="https://example.com/script2.js"></script>
     <link rel="stylesheet" id="t-2"  href="https://example.com/style.css" id="style-1">
    <link rel="stylesheet" id="t-1 href="https://example.com/style2.css">
</head>
<body>
  <script src="http://test.com" id="t-1"></script>
  <script src="http://test1.com" id="t-2"></script>
</body>
<script src="http://test2.com" id="t-3"></script>
<script src="http://test4.com"></script>
</html>
';


// // Call the function
// $script_array = getScriptData_listingArray_childTheme($html);
// print_r($script_array);

// $metaTag = '<meta name="description" content="This is an example description.">';
// $updatedHtmlContent = add_meta_tag_after_head__childTheme($html, $metaTag);
// echo $updatedHtmlContent;




/**** adding preload for js scripts******/
// $preloaded_scripts_header_tags = '';
// $preloaded_scripts_Array = getScriptData_listingArray_childTheme($html);

$stylesheetArray = getStylesheetData_listingArray_childTheme($html);
// print_r($stylesheetArray);
