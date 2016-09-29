;============================================================================
;  bandwidth, a benchmark to estimate memory transfer bandwidth.
;  Copyright (C) 2005-2014 by Zack T Smith.
;
;  This program is free software; you can redistribute it and/or modify
;  it under the terms of the GNU General Public License as published by
;  the Free Software Foundation; either version 2 of the License, or
;  (at your option) any later version.
;
;  This program is distributed in the hope that it will be useful,
;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  GNU General Public License for more details.
;
;  You should have received a copy of the GNU General Public License
;  along with this program; if not, write to the Free Software
;  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
;
;  The author may be reached at veritas@comcast.net.
;=============================================================================

bits	64
cpu	ia64

global	Reader
global	Writer


; Note:
; Unix ABI says integer param are put in these registers in this order:
;	rdi, rsi, rdx, rcx, r8, r9

	section .text
;------------------------------------------------------------------------------
; Name:		Reader
; Purpose:	Reads 64-bit values sequentially from an area of memory (256 bytes).
; Params:	rdi = ptr to memory area
;------------------------------------------------------------------------------
	align 64
Reader:
	mov	rax, [rdi]
	mov	rax, [8+rdi]
	mov	rax, [16+rdi]
	mov	rax, [24+rdi]
	mov	rax, [32+rdi]
	mov	rax, [40+rdi]
	mov	rax, [48+rdi]
	mov	rax, [56+rdi]
	mov	rax, [64+rdi]
	mov	rax, [72+rdi]
	mov	rax, [80+rdi]
	mov	rax, [88+rdi]
	mov	rax, [96+rdi]
	mov	rax, [104+rdi]
	mov	rax, [112+rdi]
	mov	rax, [120+rdi]
	mov	rax, [128+rdi]
	mov	rax, [136+rdi]
	mov	rax, [144+rdi]
	mov	rax, [152+rdi]
	mov	rax, [160+rdi]
	mov	rax, [168+rdi]
	mov	rax, [176+rdi]
	mov	rax, [184+rdi]
	mov	rax, [192+rdi]
	mov	rax, [200+rdi]
	mov	rax, [208+rdi]
	mov	rax, [216+rdi]
	mov	rax, [224+rdi]
	mov	rax, [232+rdi]
	mov	rax, [240+rdi]
	mov	rax, [248+rdi]

	ret

;------------------------------------------------------------------------------
; Name:		Writer
; Purpose:	Writes 64-bit value sequentially to an area of memory (256 bytes).
; Params:	rdi = ptr to memory area
; 		rsi = quad to write
;------------------------------------------------------------------------------
	align 64
Writer:
	mov	[rdi], rsi
	mov	[8+rdi], rsi
	mov	[16+rdi], rsi
	mov	[24+rdi], rsi
	mov	[32+rdi], rsi
	mov	[40+rdi], rsi
	mov	[48+rdi], rsi
	mov	[56+rdi], rsi
	mov	[64+rdi], rsi
	mov	[72+rdi], rsi
	mov	[80+rdi], rsi
	mov	[88+rdi], rsi
	mov	[96+rdi], rsi
	mov	[104+rdi], rsi
	mov	[112+rdi], rsi
	mov	[120+rdi], rsi
	mov	[128+rdi], rsi
	mov	[136+rdi], rsi
	mov	[144+rdi], rsi
	mov	[152+rdi], rsi
	mov	[160+rdi], rsi
	mov	[168+rdi], rsi
	mov	[176+rdi], rsi
	mov	[184+rdi], rsi
	mov	[192+rdi], rsi
	mov	[200+rdi], rsi
	mov	[208+rdi], rsi
	mov	[216+rdi], rsi
	mov	[224+rdi], rsi
	mov	[232+rdi], rsi
	mov	[240+rdi], rsi
	mov	[248+rdi], rsi

	ret

