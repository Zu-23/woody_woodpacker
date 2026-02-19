#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

// ---------------------------------------------------------------------
// 1. MANUAL OFFSETS (No <elf.h>)
// ---------------------------------------------------------------------
#define OFF_ENTRY     0x18
#define OFF_PHOFF     0x20
#define OFF_PHENTSIZE 0x36
#define OFF_PHNUM     0x38

#define PH_TYPE       0x00
#define PH_FLAGS      0x04
#define PH_OFFSET     0x08
#define PH_VADDR      0x10
#define PH_FILESZ     0x20
#define PH_MEMSZ      0x28

#define PT_LOAD       1
#define PF_X          1
#define PF_W          2
#define PF_R          4

// ---------------------------------------------------------------------
// 2. STUB: Print "Hello World" + Jump to OEP
// ---------------------------------------------------------------------
unsigned char stub[] = {
    // Call forward to push IP (get address of string)
    0xE8, 0x0C, 0x00, 0x00, 0x00, 
    
    // The String "Hello World\n" (12 bytes)
    'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '\n',
    
    // Code starts here (Offset 17)
    0x5E,                         // pop rsi      (RSI = Address of String)
    0x48, 0x31, 0xC0,             // xor rax, rax
    0xB0, 0x01,                   // mov al, 1    (Syscall: write)
    0x48, 0x89, 0xC7,             // mov rdi, rax (File Descriptor: 1 stdout)
    0x48, 0xC7, 0xC2, 0x0C, 0x00, 0x00, 0x00, // mov rdx, 12  (Length)
    0x0F, 0x05,                   // syscall

    // Restore Registers (Optional but good practice)
    // 0x48, 0x31, 0xC0,             // xor rax, rax

    // Jump to OEP (Offset 36)
    0x48, 0xB8,                   // mov rax, ... 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PLACEHOLDER (8 bytes)
    0xFF, 0xE0                    // jmp rax
};

// Offset inside 'stub' where we must write the Original Entry Point
#define STUB_OEP_OFFSET 37

// ---------------------------------------------------------------------
// 3. HELPER FUNCTIONS
// ---------------------------------------------------------------------

uint64_t get64(unsigned char *buf, int offset) {
    return *(uint64_t *)(buf + offset);
}

void set64(unsigned char *buf, int offset, uint64_t value) {
    *(uint64_t *)(buf + offset) = value;
}

uint32_t get32(unsigned char *buf, int offset) {
    return *(uint32_t *)(buf + offset);
}

void set32(unsigned char *buf, int offset, uint32_t value) {
    *(uint32_t *)(buf + offset) = value;
}

uint16_t get16(unsigned char *buf, int offset) {
    return *(uint16_t *)(buf + offset);
}

void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <target_binary>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        die("Open failed");

    off_t original_size = lseek(fd, 0, SEEK_END);
    if (original_size < 0)
        die("lseek failed");

    lseek(fd, 0, SEEK_SET);

    unsigned char *buffer = malloc(original_size);
    if (!buffer)
        die("Malloc failed");

    if (read(fd, buffer, original_size) != original_size)
        die("Read failed");
    close(fd);

    // Verify Magic: 0x7F 'E' 'L' 'F'
    if (buffer[0] != 0x7F || buffer[1] != 'E' || buffer[2] != 'L') {
        printf("Error: Not an ELF file.\n");
        free(buffer);
        return 1;
    }

    // --- STEP B: Save Original Entry Point ---
    uint64_t old_entry = get64(buffer, OFF_ENTRY);
    printf("[*] Original Entry Point: 0x%lx\n", old_entry);

    // Patch Stub with OEP (Write old_entry into the placeholder)
    *(uint64_t *)(stub + STUB_OEP_OFFSET) = old_entry;

    // --- STEP C: Find Last PT_LOAD Segment ---
    uint64_t ph_off = get64(buffer, OFF_PHOFF);
    uint16_t ph_num = get16(buffer, OFF_PHNUM);
    uint16_t ph_size = get16(buffer, OFF_PHENTSIZE);

    int target_idx = -1;
    uint64_t max_offset = 0;

    for (int i = 0; i < ph_num; i++) {
        uint64_t pos = ph_off + (i * ph_size);
        uint32_t p_type = get32(buffer, pos + PH_TYPE);
        uint64_t p_offset = get64(buffer, pos + PH_OFFSET);
        uint64_t p_filesz = get64(buffer, pos + PH_FILESZ);

        if (p_type == PT_LOAD) {
            if ((p_offset + p_filesz) > max_offset) {
                max_offset = p_offset + p_filesz;
                target_idx = i;
            }
        }
    }

    if (target_idx == -1) die("No PT_LOAD found");

    // Capture target segment info
    uint64_t target_ph_pos = ph_off + (target_idx * ph_size);
    uint64_t p_vaddr = get64(buffer, target_ph_pos + PH_VADDR);
    uint64_t p_filesz = get64(buffer, target_ph_pos + PH_FILESZ);
    uint64_t p_memsz = get64(buffer, target_ph_pos + PH_MEMSZ);

    // --- STEP D: Expansion Logic ---
    uint64_t bss_gap = p_memsz - p_filesz;
    uint64_t stub_len = sizeof(stub);
    uint64_t new_file_size = original_size + bss_gap + stub_len;

    printf("[*] Expanding file size by %ld bytes (Gap + Stub)\n", bss_gap + stub_len);

    unsigned char *new_buffer = malloc(new_file_size);
    if (!new_buffer) die("Malloc new buffer failed");
    
    // 1. Copy Original
    memcpy(new_buffer, buffer, original_size);
    // 2. Zero out BSS Gap (fill valid memory space)
    memset(new_buffer + original_size, 0, bss_gap);
    // 3. Append Patched Stub
    memcpy(new_buffer + original_size + bss_gap, stub, stub_len);

    // --- STEP E: Update ELF Header (Entry Point) ---
    // New Entry = Start of Stub in Memory
    uint64_t new_entry = p_vaddr + p_memsz;
    set64(new_buffer, OFF_ENTRY, new_entry);
    printf("[*] New Entry Point: 0x%lx\n", new_entry);

    // --- STEP F: Update Program Header (Filesz, Memsz, Flags) ---
    uint64_t new_p_filesz = p_filesz + bss_gap + stub_len;
    uint64_t new_p_memsz = p_memsz + stub_len;

    set64(new_buffer, target_ph_pos + PH_FILESZ, new_p_filesz);
    set64(new_buffer, target_ph_pos + PH_MEMSZ, new_p_memsz);
    
    // Set Flags to RWX (7)
    uint32_t flags = get32(new_buffer, target_ph_pos + PH_FLAGS);
    set32(new_buffer, target_ph_pos + PH_FLAGS, flags | PF_X | PF_W | PF_R);

    // --- STEP G: Write Output ---
    // Mode 0755 = rwxr-xr-x (Decimal 493)
    // We cannot use constants like S_IRWXU because we removed <sys/stat.h>
    int new_fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 493);
    if (new_fd < 0) die("Create woody failed");

    write(new_fd, new_buffer, new_file_size);
    close(new_fd);

    printf("[SUCCESS] Created 'woody'.\n");

    free(buffer);
    free(new_buffer);
    return 0;
}