#### `eval`
 Evaluate a string as PHP code:

**Example:1**
```php
<?php
$string = "beautiful";
$time = "winter";

$str = 'This is a $string $time morning!';
echo $str. "<br>";

eval("\$str = \"$str\";");
echo $str;
?>
```

**Example:2**
```php
eval("?><?php echo 'Hi!\n'; ?>");
```