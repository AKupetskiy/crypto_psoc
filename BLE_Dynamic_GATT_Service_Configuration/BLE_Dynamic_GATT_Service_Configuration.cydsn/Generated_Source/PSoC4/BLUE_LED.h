/*******************************************************************************
* File Name: BLUE_LED.h  
* Version 2.20
*
* Description:
*  This file contains Pin function prototypes and register defines
*
********************************************************************************
* Copyright 2008-2015, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions, 
* disclaimers, and limitations in the end user license agreement accompanying 
* the software package with which this file was provided.
*******************************************************************************/

#if !defined(CY_PINS_BLUE_LED_H) /* Pins BLUE_LED_H */
#define CY_PINS_BLUE_LED_H

#include "cytypes.h"
#include "cyfitter.h"
#include "BLUE_LED_aliases.h"


/***************************************
*     Data Struct Definitions
***************************************/

/**
* \addtogroup group_structures
* @{
*/
    
/* Structure for sleep mode support */
typedef struct
{
    uint32 pcState; /**< State of the port control register */
    uint32 sioState; /**< State of the SIO configuration */
    uint32 usbState; /**< State of the USBIO regulator */
} BLUE_LED_BACKUP_STRUCT;

/** @} structures */


/***************************************
*        Function Prototypes             
***************************************/
/**
* \addtogroup group_general
* @{
*/
uint8   BLUE_LED_Read(void);
void    BLUE_LED_Write(uint8 value);
uint8   BLUE_LED_ReadDataReg(void);
#if defined(BLUE_LED__PC) || (CY_PSOC4_4200L) 
    void    BLUE_LED_SetDriveMode(uint8 mode);
#endif
void    BLUE_LED_SetInterruptMode(uint16 position, uint16 mode);
uint8   BLUE_LED_ClearInterrupt(void);
/** @} general */

/**
* \addtogroup group_power
* @{
*/
void BLUE_LED_Sleep(void); 
void BLUE_LED_Wakeup(void);
/** @} power */


/***************************************
*           API Constants        
***************************************/
#if defined(BLUE_LED__PC) || (CY_PSOC4_4200L) 
    /* Drive Modes */
    #define BLUE_LED_DRIVE_MODE_BITS        (3)
    #define BLUE_LED_DRIVE_MODE_IND_MASK    (0xFFFFFFFFu >> (32 - BLUE_LED_DRIVE_MODE_BITS))

    /**
    * \addtogroup group_constants
    * @{
    */
        /** \addtogroup driveMode Drive mode constants
         * \brief Constants to be passed as "mode" parameter in the BLUE_LED_SetDriveMode() function.
         *  @{
         */
        #define BLUE_LED_DM_ALG_HIZ         (0x00u) /**< \brief High Impedance Analog   */
        #define BLUE_LED_DM_DIG_HIZ         (0x01u) /**< \brief High Impedance Digital  */
        #define BLUE_LED_DM_RES_UP          (0x02u) /**< \brief Resistive Pull Up       */
        #define BLUE_LED_DM_RES_DWN         (0x03u) /**< \brief Resistive Pull Down     */
        #define BLUE_LED_DM_OD_LO           (0x04u) /**< \brief Open Drain, Drives Low  */
        #define BLUE_LED_DM_OD_HI           (0x05u) /**< \brief Open Drain, Drives High */
        #define BLUE_LED_DM_STRONG          (0x06u) /**< \brief Strong Drive            */
        #define BLUE_LED_DM_RES_UPDWN       (0x07u) /**< \brief Resistive Pull Up/Down  */
        /** @} driveMode */
    /** @} group_constants */
#endif

/* Digital Port Constants */
#define BLUE_LED_MASK               BLUE_LED__MASK
#define BLUE_LED_SHIFT              BLUE_LED__SHIFT
#define BLUE_LED_WIDTH              1u

/**
* \addtogroup group_constants
* @{
*/
    /** \addtogroup intrMode Interrupt constants
     * \brief Constants to be passed as "mode" parameter in BLUE_LED_SetInterruptMode() function.
     *  @{
     */
        #define BLUE_LED_INTR_NONE      ((uint16)(0x0000u)) /**< \brief Disabled             */
        #define BLUE_LED_INTR_RISING    ((uint16)(0x5555u)) /**< \brief Rising edge trigger  */
        #define BLUE_LED_INTR_FALLING   ((uint16)(0xaaaau)) /**< \brief Falling edge trigger */
        #define BLUE_LED_INTR_BOTH      ((uint16)(0xffffu)) /**< \brief Both edge trigger    */
    /** @} intrMode */
/** @} group_constants */

/* SIO LPM definition */
#if defined(BLUE_LED__SIO)
    #define BLUE_LED_SIO_LPM_MASK       (0x03u)
#endif

/* USBIO definitions */
#if !defined(BLUE_LED__PC) && (CY_PSOC4_4200L)
    #define BLUE_LED_USBIO_ENABLE               ((uint32)0x80000000u)
    #define BLUE_LED_USBIO_DISABLE              ((uint32)(~BLUE_LED_USBIO_ENABLE))
    #define BLUE_LED_USBIO_SUSPEND_SHIFT        CYFLD_USBDEVv2_USB_SUSPEND__OFFSET
    #define BLUE_LED_USBIO_SUSPEND_DEL_SHIFT    CYFLD_USBDEVv2_USB_SUSPEND_DEL__OFFSET
    #define BLUE_LED_USBIO_ENTER_SLEEP          ((uint32)((1u << BLUE_LED_USBIO_SUSPEND_SHIFT) \
                                                        | (1u << BLUE_LED_USBIO_SUSPEND_DEL_SHIFT)))
    #define BLUE_LED_USBIO_EXIT_SLEEP_PH1       ((uint32)~((uint32)(1u << BLUE_LED_USBIO_SUSPEND_SHIFT)))
    #define BLUE_LED_USBIO_EXIT_SLEEP_PH2       ((uint32)~((uint32)(1u << BLUE_LED_USBIO_SUSPEND_DEL_SHIFT)))
    #define BLUE_LED_USBIO_CR1_OFF              ((uint32)0xfffffffeu)
#endif


/***************************************
*             Registers        
***************************************/
/* Main Port Registers */
#if defined(BLUE_LED__PC)
    /* Port Configuration */
    #define BLUE_LED_PC                 (* (reg32 *) BLUE_LED__PC)
#endif
/* Pin State */
#define BLUE_LED_PS                     (* (reg32 *) BLUE_LED__PS)
/* Data Register */
#define BLUE_LED_DR                     (* (reg32 *) BLUE_LED__DR)
/* Input Buffer Disable Override */
#define BLUE_LED_INP_DIS                (* (reg32 *) BLUE_LED__PC2)

/* Interrupt configuration Registers */
#define BLUE_LED_INTCFG                 (* (reg32 *) BLUE_LED__INTCFG)
#define BLUE_LED_INTSTAT                (* (reg32 *) BLUE_LED__INTSTAT)

/* "Interrupt cause" register for Combined Port Interrupt (AllPortInt) in GSRef component */
#if defined (CYREG_GPIO_INTR_CAUSE)
    #define BLUE_LED_INTR_CAUSE         (* (reg32 *) CYREG_GPIO_INTR_CAUSE)
#endif

/* SIO register */
#if defined(BLUE_LED__SIO)
    #define BLUE_LED_SIO_REG            (* (reg32 *) BLUE_LED__SIO)
#endif /* (BLUE_LED__SIO_CFG) */

/* USBIO registers */
#if !defined(BLUE_LED__PC) && (CY_PSOC4_4200L)
    #define BLUE_LED_USB_POWER_REG       (* (reg32 *) CYREG_USBDEVv2_USB_POWER_CTRL)
    #define BLUE_LED_CR1_REG             (* (reg32 *) CYREG_USBDEVv2_CR1)
    #define BLUE_LED_USBIO_CTRL_REG      (* (reg32 *) CYREG_USBDEVv2_USB_USBIO_CTRL)
#endif    
    
    
/***************************************
* The following code is DEPRECATED and 
* must not be used in new designs.
***************************************/
/**
* \addtogroup group_deprecated
* @{
*/
#define BLUE_LED_DRIVE_MODE_SHIFT       (0x00u)
#define BLUE_LED_DRIVE_MODE_MASK        (0x07u << BLUE_LED_DRIVE_MODE_SHIFT)
/** @} deprecated */

#endif /* End Pins BLUE_LED_H */


/* [] END OF FILE */
