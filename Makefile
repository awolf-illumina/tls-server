##########################################################################################################################
# File automatically-generated by tool: [projectgenerator] version: [3.18.0-B7] date: [Thu Feb 23 16:00:59 PST 2023]
##########################################################################################################################

# ------------------------------------------------
# Generic Makefile (based on gcc)
#
# ChangeLog :
#	2017-02-10 - Several enhancements + project update mode
#   2015-07-22 - first version
# ------------------------------------------------

######################################
# target
######################################
TARGET = tls-server


######################################
# building variables
######################################
# debug build?
DEBUG = 1
# optimization
OPT = -Og


#######################################
# paths
#######################################
# Build path
BUILD_DIR = build

######################################
# source
######################################
# C sources
C_SOURCES :=  
C_SOURCES += Core/Src/main.c
C_SOURCES += Core/Src/stm32h7xx_it.c
C_SOURCES += Core/Src/stm32h7xx_hal_msp.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_cortex.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_tim.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_tim_ex.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_rcc.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_rcc_ex.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_flash.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_flash_ex.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_gpio.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_hsem.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_dma.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_dma_ex.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_mdma.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_pwr.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_pwr_ex.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_i2c.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_i2c_ex.c
C_SOURCES += Drivers/STM32H7xx_HAL_Driver/Src/stm32h7xx_hal_exti.c
C_SOURCES += Core/Src/system_stm32h7xx.c  

# ASM sources
ASM_SOURCES :=
ASM_SOURCES += startup_stm32h723xx.s

# AS includes
AS_INCLUDES = 

# C includes
C_INCLUDES :=
C_INCLUDES += -ICore/Inc
C_INCLUDES += -IDrivers/STM32H7xx_HAL_Driver/Inc
C_INCLUDES += -IDrivers/STM32H7xx_HAL_Driver/Inc/Legacy
C_INCLUDES += -IDrivers/CMSIS/Device/ST/STM32H7xx/Include
C_INCLUDES += -IDrivers/CMSIS/Include

#######################################
# binaries
#######################################
PREFIX = arm-none-eabi-
# The gcc compiler bin path can be either defined in make command via GCC_PATH variable (> make GCC_PATH=xxx)
# either it can be added to the PATH environment variable.
ifdef GCC_PATH
CC = $(GCC_PATH)/$(PREFIX)gcc
AS = $(GCC_PATH)/$(PREFIX)gcc -x assembler-with-cpp
CP = $(GCC_PATH)/$(PREFIX)objcopy
SZ = $(GCC_PATH)/$(PREFIX)size
else
CC = $(PREFIX)gcc
AS = $(PREFIX)gcc -x assembler-with-cpp
CP = $(PREFIX)objcopy
SZ = $(PREFIX)size
endif
HEX = $(CP) -O ihex
BIN = $(CP) -O binary -S
 
#######################################
# CFLAGS
#######################################
# cpu
CPU = -mcpu=cortex-m7

# fpu
FPU = -mfpu=fpv5-d16

# float-abi
FLOAT-ABI = -mfloat-abi=hard

# mcu
MCU = $(CPU) -mthumb $(FPU) $(FLOAT-ABI)

# macros for gcc
# AS defines
AS_DEFS = 

# C defines
C_DEFS := 
C_DEFS += -DUSE_HAL_DRIVER
C_DEFS += -DSTM32H723xx

# compile gcc flags
ASFLAGS = $(MCU) $(AS_DEFS) $(AS_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections

CFLAGS += $(MCU) $(C_DEFS) $(C_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections

ifeq ($(DEBUG), 1)
CFLAGS += -g -gdwarf-2
endif


# Generate dependency information
CFLAGS += -MMD -MP -MF"$(@:%.o=%.d)"


#######################################
# LDFLAGS
#######################################
# link script
LDSCRIPT = STM32H723ZGTx_FLASH.ld

# libraries
LIBS = -lc -lm -lnosys 
LIBDIR = 
LDFLAGS = $(MCU) -specs=nano.specs -T$(LDSCRIPT) $(LIBDIR) $(LIBS) -Wl,-Map=$(BUILD_DIR)/$(TARGET).map,--cref -Wl,--gc-sections

# default action: build all
all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).hex $(BUILD_DIR)/$(TARGET).bin


#######################################
# build the application
#######################################
# list of objects
OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))
# list of ASM program objects
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.s=.o)))
vpath %.s $(sort $(dir $(ASM_SOURCES)))

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR) 
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(BUILD_DIR)/$(notdir $(<:.c=.lst)) $< -o $@

$(BUILD_DIR)/%.o: %.s Makefile | $(BUILD_DIR)
	$(AS) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS) Makefile
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	$(SZ) $@

$(BUILD_DIR)/%.hex: $(BUILD_DIR)/%.elf | $(BUILD_DIR)
	$(HEX) $< $@
	
$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf | $(BUILD_DIR)
	$(BIN) $< $@	
	
$(BUILD_DIR):
	mkdir $@		

#######################################
# clean up
#######################################
clean:
	-rm -fR $(BUILD_DIR)
  
#######################################
# dependencies
#######################################
-include $(wildcard $(BUILD_DIR)/*.d)

# *** EOF ***