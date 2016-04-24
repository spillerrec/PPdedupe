#PPdedupe for AA2
 
A small tool to reduce the file size of PP archives containing duplicate files. (AA2 only)

###Usage
```
PPdedupe pp-file [pp-file [...]]
```
Drag-and-drop PP files onto the executable. Multiple files can be dropped at once.
Once it is done processing, there will be a `input-filename.pp.deduped.pp` in the same folder as `input.filename.pp`.

###Technical details
The PP archives are split into a header and a data section. The header section contains a description of all files in the archive, and specifies where in the data section the file is located. Since each file is encrypted separately in the data section, duplicate files are stored in the exact same way.

PPdedupe calculates a CRC32 checksum for each file, and then checks if there are any other files which has the same checksum. If matches are found, an exact comparison is done to avoid the rare chance of a hash collision.
The offsets for the data section is then changed so duplicate files point to the same area in the data section. The unused area is then removed (and offsets of all other files are updated accordantly). 

###Shout-out
Thanks to the creators of SB3Utility for releasing the source code, as I used this to learn how the PP format worked.
https://github.com/enimaroah/SB3Utility