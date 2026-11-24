# Stagefright демо — CVE-2015-1538 бүхэл тооны overflow → heap overflow

ICSI251 нэмэлт онооны даалгавар. Багийн демо (заавал, 2 хүн).
С.Тэмүүлэн (22B1NUM6637) · Э.Хангарьд (22B1NUM4730)

## Юу харуулж байна вэ

`libStagefright` дэх `SampleTable::setSampleToChunkParams` MP4 файлаас
entry-ийн тоог (`count`) уншаад `count * sizeof(entry)` байт буфер
хуваарилдаг байв. 32 бит `size_t` дээр энэ үржвэр wrap хийснээр буфер хэт бага
хуваарилагдаж, дараа нь `count` удаа бичихэд **heap buffer overflow** үүснэ.

`demo.c` нь энэ механизмыг хамгийн бага хэлбэрээр давтана:

| Алхам | Утга |
|---|---|
| `count` (файлаас) | `0x40000001` (1 073 741 825) |
| `entry` хэмжээ | 8 байт |
| Хэрэгтэй (64 бит) | `0x2_00000008` = 8.5 ГБ |
| `bytes` (32 бит) | `0x00000008` = **8 байт** ← wrap |
| `malloc(bytes)` | 8 байт хуваарилна |
| Бичих давталт | `count` удаа → хил давна |

64 бит host дээр 32 бит truncation-ийг давтахын тулд арифметикийг `uint32_t`-ээр
тодорхой хийсэн (жинхэнэ код 32 бит Android дээр `size_t` ашигласан).

## Ажиллуулах

Курсын сервер дээр (Debian 13, gcc 14.2.0, valgrind 3.24):

```
bash run.sh
```

AddressSanitizer энэ сервер дээр ажиллахгүй: `ulimit -v` нь 4 ГБ-аар хатуу
хязгаарлагдсан тул ASan-ийн shadow memory (~16 ТБ) reserve хийж чадахгүй. Иймд
илрүүлэгчээр **valgrind memcheck**-ийг ашигласан. `--exit-on-first-error=yes`
нь wrap-ийн дараах 10^9 давталтыг гүйцэхээс сэргийлж, эхний буруу бичилт дээр
зогсооно.

## Хүлээгдэж буй үр дүн

`demo-output.txt`-д хадгалсан. Гол мөр:

```
needed (64-bit)  = 0x200000008 byte (8589934600)
bytes  (32-bit)  = 0x00000008 byte (8)  <-- wrap!
...
entry 0-г offset 0-д бичлээ
==...== Invalid write of size 8
==...==    by 0x... main (demo.c:63)
==...==  Address 0x... is 0 bytes after a block of size 8 alloc'd
==...==    by 0x... main (demo.c:51)
```

Арифметикийн алдаа (Лекц 02–03: unsigned overflow, truncation) шууд санах ойн
алдаа (CS:APP 3-р бүлэг: heap buffer overflow) болж хувирсныг нэг трэйсэд
харуулж байна.

## Файлууд

- `demo.c` — демо эх код
- `run.sh` — build + valgrind ажиллуулах скрипт
- `demo-output.txt` — серверээс авсан гүйлтийн бодит гаралт
- `demo-overflow.mp4` — терминал гүйлтийн бичлэг, Windows Terminal загвар (зогсоох боломжтой video)
- `demo-overflow.gif` — мөн GIF хувилбар
- `overflow-chain.mp4` — халдлагын гинжин хэлхээний animation (MMS → RCE), алхам алхмаар
