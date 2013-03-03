fake_np可以将你自己的ISO伪装成PSN下载的格式,可以在OFW下直接运行,无需各种CFW.


你需要一个合法的PSN游戏作为种子.这个PSN游戏可以是一个demo,也可以是一个购买的游戏.无论是哪一种,如果运行时需要license文件,那么伪装后的游戏也需要同样的license文件.fake_np内置了三个demo的种子.

fake_np v1.0的新特性:
 - 支持OFW 6.60
 - 支持数据压缩
 - 内置的种子最大支持1.1G(1197932544)的ISO
 - 更实用的命令行参数

使用方法:

fake_np [-b base_name] [-c] [-e] [iso_name] [pbp_name]
    -b base_name: 指定一个PSN游戏作为种子.如果没有指定,使用内置的种子
    -w          : 与[-b]一起使用,生成一个很小的种子文件.
    -c          : 打开压缩支持
    iso_name    : 你希望伪装的ISO文件. 如果没有指定,默认为"NP.ISO".
    pbp_name    : 伪装后的输出. 如果没有指定,默认为"EBOOT.PBP".

注意事项:
1. 如果提示"The EBOOT.BIN in iso is a ELF file", 那么请用附带的seboot.exe先对EBOOT.BIN进行签名,或者找到原版的EBOOT.BIN
2. 单独用fake_np -b xxx 则显示游戏的相关信息.


Fake_NP v1.0 by tpu
  This program can put your ISO/homebrew into a PSN PBP file
  The faked PBP file can be load from OFW.

New features:
  support OFW 6.60
  support data compress
  support max ISO size of 1.1G

How to use:
  fake_np [-b base_name] [-c] [iso_name] [pbp_name]
    -b base_name: select a valid PSN game as base. if empty, use buitin base.
    -w          : work with -b, save a small header of game.
    -c          : compress data.
    iso_name    : the game you want to fake. if empty, default as "NP.ISO".
    pbp_name    : the fake result. if empty, default as "EBOOT.PBP".

Notes:
  If you get this message: "The EBOOT.BIN in iso is a ELF file",
  please sign your EBOOT.BIN first(use my seboot.exe), or find origin file.
  you can found the source code here:
    http://www.kusodev.org/hg/kirk_engine

Thanks:
CipherUpdate & kono for their NP Decryptor
Mathieulh, kgsws, SilverSpring, Davee and the peoples who worked on kirk research


