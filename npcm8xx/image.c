/*
 * Boot image parsing and loading.
 *
 * Copyright 2022 Google LLC
 * Copyright (c) Nuvoton Technology Corporation.
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
#define CLK_CLKSEL 0x04
#define CLK_CLKSEL_DEFAULT 0x1f18fc9
#define FIU_DRD_CFG 0x00
#define UART0 0xf0000000
#define UART_TX 0x00

#define BMC_ANCHOR_OFFSET 0x0
#define BB_ANCHOR_VALUE 0x4F4F54AA5508500A
#define BL31_ANCHOR_VALUE 0x43504E31334C420A
#define TEE_ANCHOR_VALUE 0x43504E5F4545540A
#define UBOOT_ANCHOR_VALUE 0x4C42544F4F42550A
#define BMC_FWLENGTH_OFFSET 0x1FC
#define BMC_IMAGE_OFFSET 0x200
#define BMC_TAG_SIZE 64
// #define BB_BASE 0x80000
static uint32_t BB_BASE = 0; // make BB_BASE changeable
#define BMC_DEST_ADDR_OFFSET 0x1F8

#define GCR_PHYS_BA     0xF0800000
#define TIP_CTRL_BA     0xF080D000
#define SCRPAD          0x13C
#define SCRPAD2         0xE08
#define CP2BST2         0x004
/*
 * This structure must reside at offset 0x100 in SRAM.
 *
 * See the Check_ROMCode_Status function in the Nuvoton bootblock:
 * https://github.com/Nuvoton-Israel/bootblock/blob/master/Src/bootblock_main.c#L795
 */
struct rom_status
{
    uint8_t reserved[12];
    uint8_t start_tag[8];
    uint32_t status;
} rom_status __attribute__((section(".data.rom_status"))) = {
    .status = 0x21, /* SPI0 CS0 offset 0 */
};

struct image_info
{
    uintptr_t base_addr;
    uintptr_t tag_offset;
    uintptr_t fwlength_offset;
    uintptr_t fw_offset;
    uint64_t tag;
    uint8_t tag_size;
} image_info;

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

static uint64_t image_read_u64(uintptr_t base, uintptr_t offset)
{
    return *(uint64_t *)(base + offset);
}

static void uputc(char c)
{
    reg_write(UART0, UART_TX, c);
}

static void uputs(const char *s)
{
    for (int i = 0; s[i]; i++)
    {
        uputc(s[i]);
    }
}

static void uputx(uint32_t x)
{
    int ndigits = sizeof(x) * 2;

    uputc('0');
    uputc('x');

    for (int i = 0; i < ndigits; i++)
    {
        uint32_t d = x >> ((ndigits - i - 1) * 4);
        d &= 0xf;
        if (0 <= d && d < 10)
        {
            uputc('0' + d);
        }
        else
        {
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
    for (int i = 0; (c = fmt[i]); i++)
    {
        switch (c)
        {
        case '%':
            p = 1;
            continue;
        case 's':
            if (p)
            {
                uputs(va_arg(va, const char *));
                p = 0;
                continue;
            }
            break;
        case 'x':
            if (p)
            {
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

void copy_boot_image(uintptr_t dest_addr, uintptr_t src_addr, int32_t len,
    const char* name)
{
    uint32_t *dst = (uint32_t *)dest_addr;
    uint32_t *src = (uint32_t *)src_addr;

    uprintf("Copying %s from %x to %x, size %x...", name, src_addr, dest_addr, len);
    while (len > 0)
    {
        if ((len / 4) % 10000 == 0)
        {
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

int32_t get_next_image(struct image_info *image, uintptr_t *target_addr)
{
    uint64_t tag = 0;
    uint32_t value = 0;

    if (image->tag_size == 32)
        tag = (uint64_t)image_read_u32(SPI0CS0, image->base_addr + image->tag_offset);
    else if (image->tag_size == 64)
        tag = image_read_u64(SPI0CS0, image->base_addr + image->tag_offset);

    if (image->tag != tag)
        return -1;

    value = image_read_u32(SPI0CS0, image->base_addr + image->fwlength_offset);
    value += image->base_addr + image->fw_offset;

    *target_addr = (uintptr_t)(0xFFFFF000 & (value + 0xFFF));
    return 0;
}

int32_t get_bb_base(struct image_info *image)
{
    uint64_t tag = 0; // BB TAG is 64 bits
    // search pre-define bb offset, 0, 512K, 2M, and 4M
    uint32_t const DEFAULT_BB_BASE[] = {0x0, 0x80000, 0x200000, 0x400000};
    uint32_t i;
    for (i = 0; i < sizeof(DEFAULT_BB_BASE); i++)
    {
        tag = image_read_u64(SPI0CS0, DEFAULT_BB_BASE[i] + image->tag_offset);
        if (tag ==  image->tag)
        {
            image->base_addr = DEFAULT_BB_BASE[i];
            uprintf("found BB header at: %x\n", image->base_addr);
            return DEFAULT_BB_BASE[i];
        }
    }

    // search range 1M ~ 16M for each 512K
    uputs("Cannot find BB at default offset, search it...\n");
    for (i = 0x100000; i < 0x1000000; i += 0x80000)
    {
        tag = image_read_u64(SPI0CS0, i + image->tag_offset);
        if (tag ==  image->tag)
        {
            image->base_addr = i;
            return i;
        }
    }
    uputs("No BB TAG found\n");
    return -1;
}

int32_t load_bmc_image(uintptr_t *dest_addr)
{
    struct image_info image;
    uintptr_t image_addr = 0, img_dest_addr;
    uint32_t len;

    image_addr = image.base_addr = BB_BASE;
    image.tag_offset = BMC_ANCHOR_OFFSET;
    image.fwlength_offset = BMC_FWLENGTH_OFFSET;
    image.fw_offset = BMC_IMAGE_OFFSET;
    image.tag = BB_ANCHOR_VALUE;
    image.tag_size = BMC_TAG_SIZE;
    image_addr = get_bb_base(&image);
    if (image_addr < 0)
        return -1;
#define BB_DEST 0xFFFB0000
    len = image_read_u32(SPI0CS0, image.base_addr + BMC_FWLENGTH_OFFSET);
    copy_boot_image(BB_DEST, SPI0CS0 + image_addr, len, "BB");
    *dest_addr = BB_DEST + BMC_IMAGE_OFFSET;
    if (image_addr == 0)
    {
        // no tip case
        uputs("no tip case\n");
        *dest_addr = SPI0CS0 + BMC_IMAGE_OFFSET; // need to confirm
        return 0;
    }
    if (get_next_image(&image, &image_addr))
        return -1;

    // Load BL31 image
    image.base_addr = image_addr;
    image.tag = BL31_ANCHOR_VALUE;
    if (get_next_image(&image, &image_addr))
        return -1;
    img_dest_addr = image_read_u32(SPI0CS0, image.base_addr + BMC_DEST_ADDR_OFFSET);
    len = image_read_u32(SPI0CS0, image.base_addr + BMC_FWLENGTH_OFFSET);
    copy_boot_image(img_dest_addr, SPI0CS0 + image.base_addr, len, "BL31");
    //*dest_addr = img_dest_addr + BMC_IMAGE_OFFSET;
    // write BL31 address to Scratch Pad Register
    reg_write(GCR_PHYS_BA, SCRPAD, img_dest_addr + BMC_IMAGE_OFFSET);
    reg_write(GCR_PHYS_BA, SCRPAD2, img_dest_addr + BMC_IMAGE_OFFSET);

    // Load TEE image
    image.base_addr = image_addr;
    image.tag = TEE_ANCHOR_VALUE;
    if (get_next_image(&image, &image_addr))
        return -1;
    img_dest_addr = image_read_u32(SPI0CS0, image.base_addr + BMC_DEST_ADDR_OFFSET);
    len = image_read_u32(SPI0CS0, image.base_addr + BMC_FWLENGTH_OFFSET);
    copy_boot_image(img_dest_addr, SPI0CS0 + image.base_addr, len, "OPTEE");

    // Load U-Boot image
    image.base_addr = image_addr;
    image.tag = UBOOT_ANCHOR_VALUE;
    if (get_next_image(&image, &image_addr))
        return -1;
    img_dest_addr = image_read_u32(SPI0CS0, image.base_addr + BMC_DEST_ADDR_OFFSET);
    len = image_read_u32(SPI0CS0, image.base_addr + BMC_FWLENGTH_OFFSET);
    copy_boot_image(img_dest_addr, SPI0CS0 + image.base_addr, len, "U-Boot");
    //*dest_addr = img_dest_addr + BMC_IMAGE_OFFSET;

    return 0;
}

uintptr_t load_boot_image(void)
{
    uintptr_t image_addr = 0;
    int rc;

    uputs(splash_screen);

    /* Set CLKSEL to similar values as NPCM7XX */
    reg_write(CLK, CLK_CLKSEL, CLK_CLKSEL_DEFAULT);

    rc = load_bmc_image(&image_addr);
    if (rc)
    {
        uputs("Cannot get uboot image address\n");
        return 0;
    }

    /* Set FIU to use 4 byte mode, similar to what TIP does in reality. */
    reg_write(FIU0, FIU_DRD_CFG, 0x0301100b);
    uprintf("Boot FW from %x\n", image_addr);

    return image_addr;
    //return 0x6208000;
}
