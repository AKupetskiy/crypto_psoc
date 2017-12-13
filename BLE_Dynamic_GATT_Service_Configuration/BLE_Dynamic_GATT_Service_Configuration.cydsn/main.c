/******************************************************************************
* Project Name		: BLE_Dynamic_GATT_Service_Configuration
* File Name			: main.c
* Version 			: 1.0
* Device Used		: CY8C4247LQI-BL483
* Hardware          : CY8CKIT-042-BLE
* Software Used		: PSoC Creator 3.1 SP1
* Compiler    		: ARM GCC 4.8.4
* Owner				: mady@cypress.com
*
********************************************************************************/

#include <project.h>
#include "ecc_crypto.h"
#include "ak_aes_crypto.h"
#include "uECC.h"

#define FALSE                               (0)
#define ALL_OFF                             (0)

/***************************************
*        Global variables
***************************************/
ak_aes_context *aes_ccm_ctx;
uint8_t *sharedSecret;
uint8_t *remotePublicKey;
uint8_t *localPrivateKey;
uint8_t *localPublicKey;

/***************************************
*        Function declarations
***************************************/
void NotifyServChanged(void);
void StackEventHandler(uint32 event, void *eventParam);

void startRoutine();
void setupECCDependencies();
void clearLocalKeys();
void clearSecret();
unsigned sendPublicKey(uint8_t *localPublicKey);
unsigned sendSignature(uint8_t *signature);

static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of 
  // random noise). This can take a long time to generate random data if the result of analogRead(0) 
  // doesn't change very frequently.
    unsigned idx = 0;
    unsigned sliceIdx = 0;
    
    while (idx < size) {
	    uint8 slice[8] = {0};
        CYBLE_API_RESULT_T result = CyBle_GenerateRandomNumber(slice);
	    if (result == CYBLE_ERROR_OK ) {

            sliceIdx = 0;
            while (sliceIdx < 8) {
                dest[idx] = slice[sliceIdx];
                ++idx;
                ++sliceIdx;
            }
        } else {
            return 0;   
        }
	}

  return 1;
}

unsigned sendPublicKey(uint8_t *localPublicKey) {
    CYBLE_GATT_HANDLE_VALUE_PAIR_T publicKeyHandle;
        
	publicKeyHandle.attrHandle = CYBLE_CRYPTO_PUBLIC_KEY_CONTROL_CHAR_HANDLE;
	publicKeyHandle.value.val = localPublicKey;
	publicKeyHandle.value.len = 33;
	
	CyBle_GattsWriteAttributeValue(&publicKeyHandle, FALSE, &cyBle_connHandle, FALSE);
    
    printf("sent local public key. ");
    
    return 1;
} 

unsigned sendSignature(uint8_t *signature) {
     CYBLE_GATT_HANDLE_VALUE_PAIR_T signatureHandle;
        
	signatureHandle.attrHandle = CYBLE_CRYPTO_KEY_SIGNATURE_CONTROL_CHAR_HANDLE;
	signatureHandle.value.val = signature;
	signatureHandle.value.len = 64;
	
	CyBle_GattsWriteAttributeValue(&signatureHandle, FALSE, &cyBle_connHandle, FALSE);
    
    printf("sent local signature. ");
    
    return 1;
}

/*******************************************************************************
* Function Name: main
********************************************************************************
*
* Summary:
*  Main function.
*
* Parameters:
*  None
*
* Return:
*  None
*
*******************************************************************************/
int main()
{
    /* Enable the Global Interrupts */
    CyGlobalIntEnable;

    /* Start CYBLE component and register generic event handler */
    CyBle_Start(StackEventHandler);
    
    /* Start the UART Component for Debugging and Entering Input */
    UART_Start();
    
    setupECCDependencies();
    
    startRoutine();
}

void setupECCDependencies() {
    uECC_set_rng(&RNG);
    
    sharedSecret = (uint8_t *)malloc(32 * sizeof(uint8_t));
    remotePublicKey = (uint8_t *)malloc(33 * sizeof(uint8_t));
    localPrivateKey = (uint8_t *)malloc(32 * sizeof(uint8_t));
    localPublicKey = (uint8_t *)malloc(33 * sizeof(uint8_t));
    
    aes_ccm_ctx = (ak_aes_context *)malloc(sizeof(ak_aes_context));
}

void clearLocalKeys() {
    free(remotePublicKey);
    free(localPrivateKey);
    free(localPublicKey);
}

void clearSecret() {
    free(sharedSecret);
    free(aes_ccm_ctx);
}

void startRoutine()
{
	CYBLE_GATT_ERR_CODE_T GattErrCode = CYBLE_GATT_ERR_NONE;
	while(1)
	{
		char8 command;       /* Input from user via UART terminal */
		
		/* CyBle_ProcessEvents() allows BLE stack to process pending events */
		CyBle_ProcessEvents();
        
        //testSign();
		
		if((command = UART_UartGetChar()) != 0u)
		{
//			/* Enter D for disabling the custom RGB LED control service */
//			if ((command == 'D') || (command == 'd'))
//			{
//				GattErrCode = CyBle_GattsDisableAttribute (CYBLE_RGB_LED_SERVICE_HANDLE);
//				
//				if (GattErrCode == CYBLE_GATT_ERR_NONE)
//				{
//					UART_UartPutString ("LED service disabled\r\n");
//					NotifyServChanged();
//				}
//				else
//				{
//					UART_UartPutString ("Attribute handle is not valid\r\n");
//				}
//			}
//		
//			/* Enter E for enabling the custom RGB LED control service */
//			if ((command == 'E') || (command == 'e'))
//			{
//				GattErrCode = CyBle_GattsEnableAttribute(CYBLE_RGB_LED_SERVICE_HANDLE);
//				if (GattErrCode == CYBLE_GATT_ERR_NONE)
//				{
//					UART_UartPutString ("LED service enabled\r\n");
//					NotifyServChanged();
//				}
//				else
//				{
//					UART_UartPutString ("Attribute handle is not valid\r\n");
//				}
//			} 
            /* Enter E for restarting bt advertisement */
			if ((command == 'R') || (command == 'r') || (command == 'D') || (command == 'd'))
			{
                if (CyBle_GetState() != CYBLE_STATE_ADVERTISING) {
                    CYBLE_API_RESULT_T apiResult = CYBLE_ERROR_OK;
                    apiResult = CyBle_GappStartAdvertisement(CYBLE_ADVERTISING_FAST);
                    if (apiResult != CYBLE_ERROR_OK)
                    {
                        printf ("\r\nRestarting advertisement failed, status =0x%x",apiResult);
                    }
                    else
                    {
                        printf ("\r\nRestarting advertisement..\r\n");
                    }
                }
            }
		}
	}
}

/*******************************************************************************
* Function Name: NotifyServChanged()
********************************************************************************
*
* Summary:
*   Sends a service changed notification to the Master
*
* Parameters:
*   None
*
* Return:
*   None
*
*******************************************************************************/
//void NotifyServChanged(void)
//{
//    CYBLE_API_RESULT_T apiResult = CYBLE_ERROR_OK;
//    CYBLE_GATT_ERR_CODE_T apiGattErrCode = 0;
//    uint32 value;
//    CYBLE_GATT_HANDLE_VALUE_PAIR_T    handleValuePair;
//    
//    /* The Handle of the 1st and the last service affected are sent in the parameter 'value' */
//    value = (CYBLE_RGB_LED_SERVICE_HANDLE) << 16u | 
//            (CYBLE_RGB_LED_RGB_LED_CONTROL_CHARACTERISTIC_USER_DESCRIPTION_DESC_HANDLE);
//    handleValuePair.value.val = (uint8 *)&value;
//    handleValuePair.value.len = sizeof(value);
//    handleValuePair.attrHandle = cyBle_gatts.serviceChangedHandle;
//      
//    apiResult =CyBle_GattsNotification(cyBle_connHandle, &handleValuePair);
//    
//    if (apiResult != CYBLE_ERROR_OK)
//    {
//        printf ("Sending Service Changed Notification failed\r\n");
//    }
//    else
//    {
//        printf ("Service Changed Notification sent\r\n");
//    }
//    
//    /* To register the service change in the Database of the GATT Server */
//    apiGattErrCode = CyBle_GattsWriteAttributeValue(&handleValuePair, 0u, NULL,CYBLE_GATT_DB_LOCALLY_INITIATED);
//    
//    if (apiGattErrCode != 0)
//    {
//        printf ("Service Changed Attribute DB write failed\r\n");
//    }
//     else
//    {
//        printf ("Service Changed Attribute DB write success\r\n\n");
//    }
//}

/*******************************************************************************
* Function Name: UpdateRGBled
********************************************************************************
* Summary:
* Receive the new RGB data and change the color of the RGB LED. Also, update the
* read characteristic handle so that the next read from the BLE central device
* gives present RGB color.
*
* Parameters:
*  void
*
* Return:
*  void
*
*******************************************************************************/
//void UpdateRGBled(void)
//{
//    CYBLE_GATT_HANDLE_VALUE_PAIR_T rgbHandle; /* stores RGB control data parameters */
//    
//	printf ("Updating RGB LEDs : %d\r\n",*RGBledData);
//    
//    RED_LED_Write(~ (*RGBledData & 1));
//    GREEN_LED_Write(~(( *RGBledData & 2) >> 1));
//    BLUE_LED_Write(~(( *RGBledData & 4) >>2));
//    
//	/* Update RGB control handle with new values */
//	rgbHandle.attrHandle = CYBLE_RGB_LED_RGB_LED_CONTROL_CHAR_HANDLE;
//	rgbHandle.value.val = RGBledData;
//	rgbHandle.value.len = 1;
//	
//    
//	/* Send updated RGB control handle as attribute for read by central device, so that
//	 * Client reads the new RGB color data */
//	CyBle_GattsWriteAttributeValue(&rgbHandle, FALSE, &cyBle_connHandle, FALSE);
//}

/*******************************************************************************
* Function Name: StackEventHandler
********************************************************************************
*
* Summary:
*  This is an event callback function to receive events from the CYBLE Component.
*
* Parameters:
*  uint8 event:       Event from the CYBLE component.
*  void* eventParams: A structure instance for corresponding event type. The
*                     list of event structure is described in the component
*                     datasheet.
*
* Return:
*  None
*
*******************************************************************************/
void StackEventHandler(uint32 event, void *eventParam)
{
    CYBLE_GATTS_WRITE_REQ_PARAM_T *wrReqParam;
    CYBLE_API_RESULT_T apiResult = CYBLE_ERROR_OK;
    
    switch(event)
    {
        /**********************************************************
        *                       General Events
        ***********************************************************/
        case CYBLE_EVT_STACK_ON: /* This event received when BLE component is started */
            printf ("BLE Component ON\r\n");
            /* Starts advertisement */
            if(!(CYBLE_ERROR_OK == CyBle_GappStartAdvertisement(CYBLE_ADVERTISING_FAST)))
            {
                printf ("Starting advertisement failed, status =0x%x",apiResult);
            }
            else
            {
                printf ("Starting to advertise\r\n");
            }
            break;

        /**********************************************************
        *                       GAP Events
        ***********************************************************/
        case CYBLE_EVT_GAPP_ADVERTISEMENT_START_STOP:
            /* Event received when advertisement is Started ot Stopped */
            printf("\r\n");
            if (CyBle_GetState() != CYBLE_STATE_ADVERTISING)
            {
               printf("Advertisement is disabled\r\n");
            }
            else
            {
                printf("Advertisement is enabled \r\n");
            }
            break;

        case CYBLE_EVT_GAP_DEVICE_CONNECTED:
            /* event received when connection is established */
            printf("Device connected\r\n\n");
            break;

        case CYBLE_EVT_GAP_DEVICE_DISCONNECTED:
            /* Restarting the advertisement */
            apiResult = CyBle_GappStartAdvertisement(CYBLE_ADVERTISING_FAST);
            if (apiResult != CYBLE_ERROR_OK)
            {
                printf ("\r\nRestarting advertisement failed, status =0x%x",apiResult);
            }
            else
            {
                printf ("\r\nRestarting advertisement..\r\n");
            }
            break;

        /**********************************************************
        *                       GATT Events
        ***********************************************************/
  
        case CYBLE_EVT_GATTS_WRITE_REQ:
			/* This event is received when Central device sends a Write command on an Attribute */
            wrReqParam = (CYBLE_GATTS_WRITE_REQ_PARAM_T *) eventParam;
            
            if (CYBLE_CRYPTO_PUBLIC_KEY_CONTROL_CHAR_HANDLE == wrReqParam->handleValPair.attrHandle) {
                memcpy(remotePublicKey,wrReqParam->handleValPair.value.val,33);
                printf("remote public key = ");
                vli_print(remotePublicKey,33);
                
                if (generateKeyPair(localPublicKey,localPrivateKey)) {
                    sendPublicKey(localPublicKey);
                }
            }
            
            if (CYBLE_CRYPTO_KEY_SIGNATURE_CONTROL_CHAR_HANDLE == wrReqParam->handleValPair.attrHandle) {
                if (verifySignature(remotePublicKey, wrReqParam->handleValPair.value.val)) {
                    
                    uint8_t localSignature[64] = {0};
                    createSignature(localPrivateKey,localPublicKey,localSignature);
                    sendSignature(localSignature);
                    
                    calculateSecret(remotePublicKey,localPrivateKey,sharedSecret);
                    clearLocalKeys();
                    
                    ak_aes_init(aes_ccm_ctx,sharedSecret,32);
                }
            }
            
            if (CYBLE_CRYPTO_ENCRYPTED_DATA_CONTROL_CHAR_HANDLE == wrReqParam->handleValPair.attrHandle) {
                
                uint8_t *message = (uint8_t *)malloc(sizeof(uint8_t) * wrReqParam->handleValPair.value.len - TAG_SIZE);
                
                printf("counter value = %d \n",aes_ccm_ctx->counter);
                if (!ak_aes_unpack_and_decrypt(aes_ccm_ctx,wrReqParam->handleValPair.value.val,wrReqParam->handleValPair.value.len,message)) {
                    UART_UartPutString ("message = ");
                    UART_UartPutString (message );
                    UART_UartPutString ("\n");
                } else {
                    UART_UartPutString ("cannot unpack message");
                }
                
                printf("counter value = %d \n",aes_ccm_ctx->counter);
                
                free(message);
            }
            
			/* Send the response to the write request received. */
			CyBle_GattsWriteRsp(cyBle_connHandle);
			break;
            
        case CYBLE_EVT_GATT_DISCONNECT_IND:
            {
                uint8 ledValue = ALL_OFF;
        		/* This event is received when the device is disconnected */
        		printf ("Device disconnected\r\n");  
                
                clearLocalKeys();
                clearSecret();
            }
            break;
            
            /**********************************************************
            *                       Other Events
            ***********************************************************/
        default:
            break;
    }
}

/* [] END OF FILE */
