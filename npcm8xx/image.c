/*
 * Boot image parsing and loading.
 *
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef int int32_t;

typedef __builtin_va_list va_list;
#define va_arg __builtin_va_arg
#define va_start __builtin_va_start
#define va_end __builtin_va_end

#define SPI0CS0 0x80000000
#define CLK 0xf0801000
#define FIU0 0xfb000000
#define CLK_CLKSEL  0x04
#define CLK_CLKSEL_DEFAULT 0x1f18fc9
#define FIU_DRD_CFG 0x00
#define UART0 0xf0000000
#define UART_TX 0x00

/*
 * This structure must reside at offset 0x100 in SRAM.
 *
 * See the Check_ROMCode_Status function in the Nuvoton bootblock:
 * https://github.com/Nuvoton-Israel/bootblock/blob/master/Src/bootblock_main.c#L795
 */
struct rom_status {
    uint8_t reserved[12];
    uint8_t start_tag[8];
    uint32_t status;
} rom_status __attribute__((section(".data.rom_status"))) = {
    .status = 0x21, /* SPI0 CS0 offset 0 */
};

extern void panic(const char *);

static void reg_write(uintptr_t base, uintptr_t offset, uint32_t value)
{
    asm volatile("str   %w0, [%1, %2]"
                 :
                 : "r"(value), "r"(base), "i"(offset)
                 : "memory");
}

static uint32_t image_read_u8(uintptr_t base, uintptr_t offset)
{
    return *(uint8_t *)(base + offset);
}

static uint32_t image_read_u32(uintptr_t base, uintptr_t offset)
{
    return *(uint32_t *)(base + offset);
}

static void uputc(char c)
{
    reg_write(UART0, UART_TX, c);
}

static void uputs(const char *s)
{
    for (int i = 0; s[i]; i++) {
        uputc(s[i]);
    }
}

static void uputx(uint32_t x)
{
    int ndigits = sizeof(x) * 2;

    uputc('0');
    uputc('x');

    for (int i = 0; i < ndigits; i++) {
        uint32_t d = x >> ((ndigits - i - 1) * 4);
        d &= 0xf;
        if (0 <= d && d < 10) {
            uputc('0' + d);
        } else {
            uputc('a' + d - 10);
        }
    }
}

static void uprintf(const char *fmt, ...)
{
    va_list va;
    char c;
    int p = 0;

    va_start(va, fmt);
    for (int i = 0; (c = fmt[i]); i++) {
        switch (c) {
        case '%':
            p = 1;
            continue;
        case 's':
            if (p) {
                uputs(va_arg(va, const char*));
                p = 0;
                continue;
            }
            break;
        case 'x':
            if (p) {
                uputx((uint64_t)va_arg(va, uint64_t));
                p = 0;
                continue;
            }
            break;
        }

        uputc(c);
    }
    va_end(va);
}

void copy_boot_image(uintptr_t dest_addr, uintptr_t src_addr, int32_t len)
{
    uint32_t *dst = (uint32_t *)dest_addr;
    uint32_t *src = (uint32_t *)src_addr;

    uprintf("Copying U-Boot from %x to %x, size %x...", src_addr, dest_addr, len);
    while (len > 0) {
        if ((len / 4) % 10000 == 0) {
            uputc('.');
        }
        *dst++ = *src++;
        len -= sizeof(*dst);
    }
    uprintf("done.\n");
}

static const char *splash_screen =
"             __                                     ____  __ __  ______\n"
"  ___ _   __/ /_        ____  ____  _________ ___  ( __ )/ // / / ____/\n"
" / _ \\ | / / __ \\______/ __ \\/ __ \\/ ___/ __ `__ \\/ __  / // /_/___ \\  \n"
"/  __/ |/ / /_/ /_____/ / / / /_/ / /__/ / / / / / /_/ /__  __/___/ /  \n"
"\\___/|___/_.___/     /_/ /_/ .___/\\___/_/ /_/ /_/\\____/  /_/ /_____/   \n"
"                          /_/                                          \n\n";

uintptr_t load_boot_image(void)
{
    uintptr_t dest_addr = 0x8000;

    uputs(splash_screen);

    /* Set CLKSEL to similar values as NPCM7XX */
    reg_write(CLK, CLK_CLKSEL, CLK_CLKSEL_DEFAULT);

    /* Load the U-BOOT image to DRAM */
    copy_boot_image(dest_addr, SPI0CS0 + 0x10e200, 0xa075a);
    /* Set FIU to use 4 byte mode, similar to what TIP does in reality. */
    reg_write(FIU0, FIU_DRD_CFG, 0x0301100b);

    return dest_addr;
}
