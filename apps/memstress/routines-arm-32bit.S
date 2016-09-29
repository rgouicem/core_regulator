
# ============================================================================
#  bandwidth 0.23, a benchmark to estimate memory transfer bandwidth.
#  ARM assembly module.
#  Copyright (C) 2010 by Zack T Smith.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
#  The author may be reached at 1@zsmith.co.
# =============================================================================

# Version 0.8

# Note, some instructions are not supported by the ARM CPU in the Raspberry pi 2.

.section code

.globl Writer
.globl Reader

.arm
.text
.align	

#-----------------------------------------------------------------------------
# Name: 	Writer
# Purpose:	Performs sequential write into memory, as fast as possible.
# Params:
#	r0 = address
# 	r1 = value to write
#-----------------------------------------------------------------------------
Writer:
	push	{r3-r9, lr}

	mov	r3, r1
	mov	r4, r1
	mov	r5, r1
	mov	r6, r1
	mov	r7, r1
	mov	r8, r1
	mov	r9, r1

# Does 64 transfers, 4 bytes each = 256 bytes total.
# The "stmia" instruction automatically increments r0.
        stmia   r0!, { r1, r3, r4, r5, r6, r7, r8, r9 }
        stmia   r0!, { r1, r3, r4, r5, r6, r7, r8, r9 }
        stmia   r0!, { r1, r3, r4, r5, r6, r7, r8, r9 }
        stmia   r0!, { r1, r3, r4, r5, r6, r7, r8, r9 }
        stmia   r0!, { r1, r3, r4, r5, r6, r7, r8, r9 }
        stmia   r0!, { r1, r3, r4, r5, r6, r7, r8, r9 }
        stmia   r0!, { r1, r3, r4, r5, r6, r7, r8, r9 }
        stmia   r0!, { r1, r3, r4, r5, r6, r7, r8, r9 }

# return.
	pop 	{r3-r9, pc}

#-----------------------------------------------------------------------------
# Name: 	Reader
# Purpose:	Performs sequential reads from memory, as fast as possible.
# Params:
#	r0 = address
#-----------------------------------------------------------------------------
Reader:
	push	{r2-r9, lr}

# Does 64 transfers, 4 bytes each = 256 bytes total.
# The "ldmia" instruction automatically increments r0.
	ldmia	r0!, { r2, r3, r4, r5, r6, r7, r8, r9 }
	ldmia	r0!, { r2, r3, r4, r5, r6, r7, r8, r9 }
	ldmia	r0!, { r2, r3, r4, r5, r6, r7, r8, r9 }
	ldmia	r0!, { r2, r3, r4, r5, r6, r7, r8, r9 }
	ldmia	r0!, { r2, r3, r4, r5, r6, r7, r8, r9 }
	ldmia	r0!, { r2, r3, r4, r5, r6, r7, r8, r9 }
	ldmia	r0!, { r2, r3, r4, r5, r6, r7, r8, r9 }
	ldmia	r0!, { r2, r3, r4, r5, r6, r7, r8, r9 }

# return.
	pop	{r2-r9, pc}
