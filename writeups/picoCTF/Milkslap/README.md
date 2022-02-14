
# Milkslap 

### Author: James Lynch

### Description

```
Category: Forensics

<a href="http://mercury.picoctf.net:7585/">🥛</a>

Hints:

(1) Look at the problem category

```

### Solution

Visiting the website provided, there's an image that can be controlled by the user to slap a person with milk.

We can take a look around at the website source code but there's nothing really interesting. Since, this is a forensics challenge, maybe there's something we need to do with the image that's provided. Let's download it and take a look.

![](concat_v.png)

The image seems to have many frames captured in it of the person being milkslapped. Let's get some information about the image. I use `file`, `binwalk`, `strings` and `exiftool` on the file but nothing interesting found.

PNGs can be used to hide data using LSB steganography techniques. One such tool that tries to detect hidden data is `zsteg`. In this case, it gets us the flag.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Milkslap]
└─$ zsteg concat_v.png 
imagedata           .. text: "\n\n\n\n\n\n\t\t"
b1,b,lsb,xy         .. text: "picoCTF{imag3_m4n1pul4t10n_sl4p5}\n"
b1,bgr,lsb,xy       .. <wbStego size=9706075, data="\xB6\xAD\xB6}\xDB\xB2lR\x7F\xDF\x86\xB7c\xFC\xFF\xBF\x02Zr\x8E\xE2Z\x12\xD8q\xE5&MJ-X:\xB5\xBF\xF7\x7F\xDB\xDFI\bm\xDB\xDB\x80m\x00\x00\x00\xB6m\xDB\xDB\xB6\x00\x00\x00\xB6\xB6\x00m\xDB\x12\x12m\xDB\xDB\x00\x00\x00\x00\x00\xB6m\xDB\x00\xB6\x00\x00\x00\xDB\xB6mm\xDB\xB6\xB6\x00\x00\x00\x00\x00m\xDB", even=true, mix=true, controlbyte="[">
b2,r,lsb,xy         .. file: SoftQuad DESC or font file binary
b2,r,msb,xy         .. file: VISX image file
b2,g,lsb,xy         .. file: VISX image file
b2,g,msb,xy         .. file: SoftQuad DESC or font file binary - version 15722
b2,b,msb,xy         .. text: "UfUUUU@UUU"
b4,r,lsb,xy         .. text: "\"\"\"\"\"#4D"
b4,r,msb,xy         .. text: "wwww3333"
b4,g,lsb,xy         .. text: "wewwwwvUS"
b4,g,msb,xy         .. text: "\"\"\"\"DDDD"
b4,b,lsb,xy         .. text: "vdUeVwweDFw"
b4,b,msb,xy         .. text: "UUYYUUUUUUUU"
```

##### Flag: `picoCTF{imag3_m4n1pul4t10n_sl4p5}`
