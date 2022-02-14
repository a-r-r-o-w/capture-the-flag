
# Matryoshka doll 

### Author: Susie/Pandu

### Description

```
Category: Forensics

Matryoshka dolls are a set of wooden dolls of decreasing size placed one inside another. What's the final one? Image: <a href='//mercury.picoctf.net/static/5ef2e9103d55972d975437f68175b9ab/dolls.jpg'>this</a>

Hints:

(1) Wait, you can hide files inside files? But how do you find them?

(2) Make sure to submit the flag as picoCTF{XXXXX}

```

### Solution

We are provided with an image.

![image](dolls.jpg)

The challenge description suggests that maybe there's a file placed inside the provided image, which is common in many steganography and forensics challenges. Files can be hidden in a recursive fashion or simply just appended at the end of another file, etc.

Let's find some basic information about the file using `file` and `binwalk`.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Matryoshka doll]
└─$ file dolls.jpg                                                  
dolls.jpg: PNG image data, 594 x 1104, 8-bit/color RGBA, non-interlaced
                                                                                                  
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Matryoshka doll]
└─$ binwalk dolls.jpg                                                         

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 594 x 1104, 8-bit/color RGBA, non-interlaced
3226          0xC9A           TIFF image data, big-endian, offset of first image directory: 8
272492        0x4286C         Zip archive data, at least v2.0 to extract, compressed size: 378954, uncompressed size: 383940, name: base_images/2_c.jpg
651612        0x9F15C         End of Zip archive, footer length: 22
```

There's a zip archive file base_images/2.c.jpg hidden inside the image file data. Let's try extracting it.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Matryoshka doll]
└─$ unzip dolls.jpg 
Archive:  dolls.jpg
warning [dolls.jpg]:  272492 extra bytes at beginning or within zipfile
  (attempting to process anyway)
  inflating: base_images/2_c.jpg     
                                                                                                  
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Matryoshka doll]
└─$ cd base_images                                                                            1 ⨯
                                                                                                  
┌──(arrow) 💀 [~/…/Writeups/picoCTF/Matryoshka doll/base_images]
└─$ file 2_c.jpg 
2_c.jpg: PNG image data, 526 x 1106, 8-bit/color RGBA, non-interlaced
                                                                                                  
┌──(arrow) 💀 [~/…/Writeups/picoCTF/Matryoshka doll/base_images]
└─$ binwalk 2_c.jpg                                                                   

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 526 x 1106, 8-bit/color RGBA, non-interlaced
3226          0xC9A           TIFF image data, big-endian, offset of first image directory: 8
187707        0x2DD3B         Zip archive data, at least v2.0 to extract, compressed size: 196045, uncompressed size: 201447, name: base_images/3_c.jpg
383807        0x5DB3F         End of Zip archive, footer length: 22
383918        0x5DBAE         End of Zip archive, footer length: 22
```

There seems to be another image, that's a smaller version of the original, that contains a zip archive. It most likely seems to be recursive and that there are many layers with nested zip and images files. Let's extract recursively with `binwalk`.

```bash
                                                                                                  
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/Matryoshka doll]
└─$ binwalk -evM dolls.jpg 

Scan Time:     2021-12-17 05:16:38
Target File:   /home/arrow/Desktop/capture-the-flag/Writeups/picoCTF/Matryoshka doll/dolls.jpg
MD5 Checksum:  4e20dca670f35285995d96533d0e0a69
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 594 x 1104, 8-bit/color RGBA, non-interlaced
3226          0xC9A           TIFF image data, big-endian, offset of first image directory: 8
272492        0x4286C         Zip archive data, at least v2.0 to extract, compressed size: 378954, uncompressed size: 383940, name: base_images/2_c.jpg
651612        0x9F15C         End of Zip archive, footer length: 22


Scan Time:     2021-12-17 05:16:38
Target File:   /home/arrow/Desktop/capture-the-flag/Writeups/picoCTF/Matryoshka doll/_dolls.jpg.extracted/base_images/2_c.jpg
MD5 Checksum:  4d6e68a72702eba3f2b1f95670f12ac7
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 526 x 1106, 8-bit/color RGBA, non-interlaced
3226          0xC9A           TIFF image data, big-endian, offset of first image directory: 8
187707        0x2DD3B         Zip archive data, at least v2.0 to extract, compressed size: 196045, uncompressed size: 201447, name: base_images/3_c.jpg
383807        0x5DB3F         End of Zip archive, footer length: 22
383918        0x5DBAE         End of Zip archive, footer length: 22


Scan Time:     2021-12-17 05:16:38
Target File:   /home/arrow/Desktop/capture-the-flag/Writeups/picoCTF/Matryoshka doll/_dolls.jpg.extracted/base_images/_2_c.jpg.extracted/base_images/3_c.jpg
MD5 Checksum:  03116a4e0101b30bedcf0905531c0e1f
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 428 x 1104, 8-bit/color RGBA, non-interlaced
3226          0xC9A           TIFF image data, big-endian, offset of first image directory: 8
123606        0x1E2D6         Zip archive data, at least v2.0 to extract, compressed size: 77653, uncompressed size: 79808, name: base_images/4_c.jpg
201425        0x312D1         End of Zip archive, footer length: 22


Scan Time:     2021-12-17 05:16:38
Target File:   /home/arrow/Desktop/capture-the-flag/Writeups/picoCTF/Matryoshka doll/_dolls.jpg.extracted/base_images/_2_c.jpg.extracted/base_images/_3_c.jpg.extracted/base_images/4_c.jpg
MD5 Checksum:  4e139c3a53b17b18c5fe1994dd3e7d46
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 320 x 768, 8-bit/color RGBA, non-interlaced
3226          0xC9A           TIFF image data, big-endian, offset of first image directory: 8
79578         0x136DA         Zip archive data, at least v2.0 to extract, compressed size: 64, uncompressed size: 81, name: flag.txt
79786         0x137AA         End of Zip archive, footer length: 22
```

The recursive extraction gives a flag.txt file which contains the flag.

##### Flag: `picoCTF{e3f378fe6c1ea7f6bc5ac2c3d6801c1f}`
