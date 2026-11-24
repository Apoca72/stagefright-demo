/*
 * Stagefright (CVE-2015-1538) бүхэл тооны overflow-ийн хялбаршуулсан демо.
 *
 * libStagefright дэх SampleTable::setSampleToChunkParams функц MP4 файлаас
 * entry-ийн тоог (count) уншаад, count * sizeof(entry) хэмжээтэй буфер
 * хуваарилдаг байв. 32 бит size_t дээр энэ үржвэр wrap хийж, буфер хэт бага
 * хуваарилагдана. Дараа нь count удаа бичихэд heap overflow үүснэ.
 *
 * Жинхэнэ алдаа 32 бит Android дээр 32 бит size_t-ийн улмаас гарсан. Энэ демо
 * 64 бит host дээр ажиллаж байгаа тул арифметикийг uint32_t-ээр ТОДОРХОЙ
 * хийж, 32 бит truncation-ийг давтаж байна (жинхэнэ код size_t ашигласан).
 *
 * Орчуулга: comment нь Монгол, identifier нь English (курсын дүрэм).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* MP4 атомоос уншсан мэт сэжигтэй count утга. Том сонгосон нь wrap-ийг
 * тодорхой харуулахын тулд: 0x40000001 * 8 = 0x2_00000008. */
#define ATTACKER_COUNT  0x40000001u

/* entry бүрийн хэмжээ (байт). Слайдын жишээтэй ижил: 8. */
#define ENTRY_SIZE      8u

int main(void)
{
    /* 1. Файлаас count уншина (энд attacker-ийн хяналтанд байх утга). */
    uint32_t count = ATTACKER_COUNT;
    uint32_t entry = ENTRY_SIZE;

    /* 2. count * entry-г 32 бит дээр бодно. Overflow: үр дүн 2^32-оор
     *    модульлагдаж, жинхэнэ хэрэгтэй хэмжээнээс маш бага гарна. */
    uint32_t bytes = count * entry;          /* 0x2_00000008 -> 0x00000008 */

    /* Жинхэнэ (truncate хийгээгүй) хэрэгтэй хэмжээг 64 бит дээр харьцуулж
     *    харуулъя — энэ нь malloc авах ёстой байсан хэмжээ. */
    uint64_t needed = (uint64_t)count * (uint64_t)entry;

    printf("count            = 0x%08x (%u)\n", count, count);
    printf("entry size       = %u byte\n", entry);
    printf("needed (64-bit)  = 0x%llx byte (%llu)\n",
           (unsigned long long)needed, (unsigned long long)needed);
    printf("bytes  (32-bit)  = 0x%08x byte (%u)  <-- wrap!\n", bytes, bytes);
    printf("malloc(%u) дуудаж, %u entry бичих гэж байна...\n\n", bytes, count);
    fflush(stdout);

    /* 3. Хэт бага буфер хуваарилна (ердөө 8 байт). */
    uint8_t *buf = (uint8_t *)malloc(bytes);
    if (buf == NULL) {
        perror("malloc");
        return 1;
    }

    /* 4. count удаа entry бичнэ. buf нь ердөө bytes (8) байт тул 2 дахь
     *    entry-г бичих үед л heap-ийн хил давна -> heap-buffer-overflow.
     *    valgrind memcheck эндээс алдааг барина. */
    for (uint32_t i = 0; i < count; i++) {
        /* i дэх entry-ийн эхлэл: i * entry. 32 бит дээр энэ ч бас wrap
         *    хийх ч, эхний хэдэн бичилт шууд хил давна. */
        memset(buf + (uint64_t)i * entry, 0x41, entry);   /* 'A' * entry */
        if (i < 4) {
            printf("entry %u-г offset %llu-д бичлээ\n",
                   i, (unsigned long long)((uint64_t)i * entry));
            fflush(stdout);
        }
    }

    /* Энд хүрэхгүй: valgrind 2 дахь бичилтэд процессыг зогсооно. */
    printf("overflow баригдсангүй (valgrind идэвхгүй байна уу?)\n");
    free(buf);
    return 0;
}
