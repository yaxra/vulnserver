section .text

global _jmp_esp_gadget

_jmp_esp_gadget:
    jmp esp
    ret