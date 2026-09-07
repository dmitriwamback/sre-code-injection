# Software Reverse Engineering Code Injection

<p>Demo code injection application which injects a payload into a target's <code>__TEXT</code> and <code>__text</code> sections/segments.</p>

### September 7 Log: 

<p>As of September 7, 2026, only Mach-O injection is in process of development. Additionally, code signing is not fully implemented. This makes the saved Mach-O files unable to run without crashing.</p>
<p>The first milestone is when disassembling the output file, the payload function appears in the file.</p>
<p>Next milestone is to upload a payload larger (in bytes) than the number of available bytes in the target program.</p>