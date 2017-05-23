/*--

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.


Module Name:

    atrfiltr.c

Abstract: This is an upper device filter driver sample for smartcard readers.
        This driver will filter all requests for the ATR and make sure that
        all ATRs returned match the ATR from a cold reset request.  This is
        a workaround for Estonian ID cards that can change their ATR.

        If you want to filter ATR requests for all smartcard readers 
        plugged into the system then you can install this driver as a class filter
        and make it sit below the scfiltr filter driver by adding the service
        name of this filter driver after the scfiltr filter in the registry at
        " HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\
        {50DD5230-BA8A-11D1-BF5D-0000F805F530}\UpperFilters"


Environment:

    Kernel mode only.

--*/

#include "atrfiltr.h"

#pragma warning( disable:4311 )
#pragma warning( disable:4312 )

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, AtrFilter_EvtDeviceAdd)
#pragma alloc_text (PAGE, AtrFilter_EvtIoDeviceControl)
#endif

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Installable driver initialization entry point.
    This entry point is called directly by the I/O system.

Arguments:

    DriverObject - pointer to the driver object

    RegistryPath - pointer to a unicode string representing the path,
                   to driver-specific key in the registry.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG               config;
    NTSTATUS                        status;

    DebugPrint(("ATR Filter Driver Sample - Driver Framework Edition.\n"));
    DebugPrint(("Built %s %s\n", __DATE__, __TIME__));

    //
    // Initiialize driver config to control the attributes that
    // are global to the driver. Note that framework by default
    // provides a driver unload routine. If you create any resources
    // in the DriverEntry and want to be cleaned in driver unload,
    // you can override that by manually setting the EvtDriverUnload in the
    // config structure. In general xxx_CONFIG_INIT macros are provided to
    // initialize most commonly used members.
    //

    WDF_DRIVER_CONFIG_INIT(
        &config,
        AtrFilter_EvtDeviceAdd
    );

    //
    // Create a framework driver object to represent our driver.
    //
    status = WdfDriverCreate(DriverObject,
                            RegistryPath,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &config,
                            WDF_NO_HANDLE); // hDriver optional
    if (!NT_SUCCESS(status)) {
        DebugPrint(("WdfDriverCreate failed with status 0x%x\n", status));
    }

    return status;
}

NTSTATUS
AtrFilter_EvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
    )
/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. Here you can query the device properties
    using WdfFdoInitWdmGetPhysicalDevice/IoGetDeviceProperty and based
    on that, decide to create a filter device object and attach to the
    function stack.

    If you are not interested in filtering this particular instance of the
    device, you can just return STATUS_SUCCESS without creating a framework
    device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
{
    WDF_OBJECT_ATTRIBUTES   deviceAttributes;
    NTSTATUS                status;
    WDFDEVICE               hDevice;
    PDEVICE_EXTENSION       filterExt;
    WDF_IO_QUEUE_CONFIG     ioQueueConfig;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    DebugPrint(("Enter FilterEvtDeviceAdd \n"));

    //
    // Tell the framework that you are filter driver. Framework
    // takes care of inherting all the device flags & characterstics
    // from the lower device you are attaching to.
    //
    WdfFdoInitSetFilter(DeviceInit);

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_SMARTCARD);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_EXTENSION);

    //
    // Create a framework device object.  This call will in turn create
    // a WDM deviceobject, attach to the lower stack and set the
    // appropriate flags and attributes.
    //
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &hDevice);
    if (!NT_SUCCESS(status)) {
        DebugPrint(("WdfDeviceCreate failed with status code 0x%x\n", status));
        return status;
    }

    filterExt = FilterGetData(hDevice);

    //
    // Initialize extension data.
    //
    filterExt->ColdResetAtrSize = 0;
    RtlZeroMemory(filterExt->ColdResetAtr, sizeof (filterExt->ColdResetAtr));

    //
    // Configure the default queue to be Parallel. We need this for the
    // ABSENT/PRESENT IOCTLs.  A default queue gets all the
    // requests that are not configure-fowarded using
    // WdfDeviceConfigureRequestDispatching.
    // Filter drivers should create a non-power managed queue.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
                             WdfIoQueueDispatchParallel);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoDeviceControl = AtrFilter_EvtIoDeviceControl;

    status = WdfIoQueueCreate(hDevice,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            WDF_NO_HANDLE // pointer to default queue
                            );
    if (!NT_SUCCESS(status)) {
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    return status;
}

VOID
AtrFilter_EvtIoDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
/*++

Routine Description:

    This routine is the dispatch routine for device control requests.
    Here are the specific control codes that are of interest:

    IOCTL_SMARTCARD_IS_ABSENT:
        On successful completion, clear out the stored ATR from the cold
        reset.

    IOCTL_SMARTCARD_POWER:
        On completion, store the ATR from the cold reset.  On all subsequent
        warm reset requests, make sure the ATR matches.
        If not, copy the saved ATR from the cold reset.

    IOCTL_SMARTCARD_GET_ATTRIBUTE:
        Make sure the ATR matches the value from the cold reset.
        If not, copy the saved ATR from the cold reset.

Arguments:

    Queue - Handle to the framework queue object that is associated
            with the I/O request.
    Request - Handle to a framework request object.

    OutputBufferLength - length of the request's output buffer,
                        if an output buffer is available.
    InputBufferLength - length of the request's input buffer,
                        if an input buffer is available.

    IoControlCode - the driver-defined or system-defined I/O control code
                    (IOCTL) that is associated with the request.

Return Value:

   VOID

--*/
{
    PDEVICE_EXTENSION               devExt;
    NTSTATUS                        status = STATUS_SUCCESS;
    WDFDEVICE                       hDevice;
    BOOLEAN                         forwardWithCompletionRoutine = FALSE;
    BOOLEAN                         ret = TRUE;
    WDFCONTEXT                      completionContext = WDF_NO_CONTEXT;
    WDF_REQUEST_SEND_OPTIONS        options;
    WDFMEMORY                       inputMemory = NULL;
    WDFMEMORY                       outputMemory = NULL;
    PVOID                           inputBuffer;
    ULONG                           minorIoCode;
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);


    PAGED_CODE();

    DebugPrint(("Entered AtrFilter_EvtIoDeviceControl\n"));

    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = FilterGetData(hDevice);

    switch (IoControlCode) {

    //
    // Filter request to let us know to clear out stored ATR.
    //
    case IOCTL_SMARTCARD_IS_ABSENT:
        forwardWithCompletionRoutine = TRUE;
        break;

    //
    // Filter all requests that get the ATR.
    //
    case IOCTL_SMARTCARD_POWER:
        //
        // Save the minor I/O control code.
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                                               4,
                                               &inputBuffer,
                                               NULL);
        if (NT_SUCCESS(status))
        {
            minorIoCode = *(PULONG) inputBuffer;
            completionContext = (WDFCONTEXT) minorIoCode;
        }
        forwardWithCompletionRoutine = TRUE;
        break;

    case IOCTL_SMARTCARD_GET_ATTRIBUTE:
        //
        // Filter only requests for SCARD_ATTR_ATR_STRING
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                                               4,
                                               &inputBuffer,
                                               NULL);

        if (NT_SUCCESS(status))
        {
            minorIoCode = *(PULONG) inputBuffer;
            if (minorIoCode == SCARD_ATTR_ATR_STRING)
            {
                forwardWithCompletionRoutine = TRUE;
            }
        }
        break;

    default:
        break;
    }

    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    //
    // Forward the request down. WdfDeviceGetIoTarget returns
    // the default target, which represents the device attached to us below in
    // the stack.
    //

    if (forwardWithCompletionRoutine) {

        //
        // Format the request with the input and output memory so the completion routine
        // can access the return data in order to cache it into the context area
        //
        
        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory); 

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfRequestRetrieveOutputMemory failed: 0x%x\n", status));
            outputMemory = NULL;
        }

        status = WdfRequestRetrieveInputMemory(Request, &inputMemory); 

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfRequestRetrieveInputMemory failed: 0x%x\n", status));
            inputMemory = NULL;
        }

        status = WdfIoTargetFormatRequestForIoctl(WdfDeviceGetIoTarget(hDevice),
                                                         Request,
                                                         IoControlCode,
                                                         inputMemory,
                                                         NULL,
                                                         outputMemory,
                                                         NULL);

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfIoTargetFormatRequestForIoctl failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
            return;
        }
    
        // 
        // Set our completion routine with a context area that we will save
        // the output data into
        //
        WdfRequestSetCompletionRoutine(Request,
                                       AtrFilterRequestCompletionRoutine, 
                                       completionContext);

        ret = WdfRequestSend(Request,
                             WdfDeviceGetIoTarget(hDevice),
                             WDF_NO_SEND_OPTIONS);

        if (ret == FALSE) {
            status = WdfRequestGetStatus (Request);
            DebugPrint( ("WdfRequestSend failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }

    }
    else
    {

        //
        // We are not interested in post processing the IRP so 
        // fire and forget.
        //
        WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                      WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

        ret = WdfRequestSend(Request, WdfDeviceGetIoTarget(hDevice), &options);

        if (ret == FALSE) {
            status = WdfRequestGetStatus (Request);
            DebugPrint(("WdfRequestSend failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }
        
    }

    return;
}

VOID
AtrFilterRequestCompletionRoutine(
    WDFREQUEST                  Request,
    WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    WDFCONTEXT                  Context
   )
/*++

Routine Description:

    Completion Routine

Arguments:

    Target - Target handle
    Request - Request handle
    Params - request completion params
    Context - Driver supplied context


Return Value:

    VOID

--*/
{
    NTSTATUS    status = STATUS_SUCCESS;
    WDFQUEUE    queue = WdfRequestGetIoQueue(Request);
    WDFDEVICE   device = WdfIoQueueGetDevice(queue);
    PDEVICE_EXTENSION   filterExt = FilterGetData(device);
    WDFMEMORY   output = CompletionParams->Parameters.Ioctl.Output.Buffer;
    WDF_REQUEST_PARAMETERS requestParams;
    ULONG       minorIoCode;

    UNREFERENCED_PARAMETER(Target);

    WDF_REQUEST_PARAMETERS_INIT(&requestParams);
    WdfRequestGetParameters(Request, &requestParams);

    if (CompletionParams->Type == WdfRequestTypeDeviceControl &&
        NT_SUCCESS(CompletionParams->IoStatus.Status))
    {

        switch (CompletionParams->Parameters.Ioctl.IoControlCode) {

        //
        // Filter request to let us know to clear out stored ATR.
        //
        case IOCTL_SMARTCARD_IS_ABSENT:
            //
            // Re-initialize saved ATR.
            //
            if (filterExt->ColdResetAtrSize != 0)
            {
                filterExt->ColdResetAtrSize = 0;
                RtlZeroMemory(filterExt->ColdResetAtr, sizeof (filterExt->ColdResetAtr));
            }
            break;

        //
        // Filter all requests that get the ATR.
        //
        case IOCTL_SMARTCARD_GET_ATTRIBUTE:
            //
            // We know that we filtered only requests for SCARD_ATTR_ATR_STRING.
            // Copy the saved ATR.
            //
            if ((filterExt->ColdResetAtrSize != 0) &&
                (requestParams.Parameters.DeviceIoControl.OutputBufferLength >= filterExt->ColdResetAtrSize))
            {
                WdfRequestSetInformation(Request, filterExt->ColdResetAtrSize);
                CompletionParams->Parameters.Ioctl.Output.Length = filterExt->ColdResetAtrSize;
                CompletionParams->IoStatus.Information = filterExt->ColdResetAtrSize;
                WdfMemoryCopyFromBuffer(output,
                                        0,
                                        filterExt->ColdResetAtr,
                                        filterExt->ColdResetAtrSize);
            }
            break;

        case IOCTL_SMARTCARD_POWER:
            //
            // Check to see what kind of power reset this is.
            //
            minorIoCode = (ULONG) Context;

            switch (minorIoCode)
            {
            case SCARD_COLD_RESET:
                //
                // Clear and save the ATR.
                //
                if (filterExt->ColdResetAtrSize != 0)
                {
                    filterExt->ColdResetAtrSize = 0;
                    RtlZeroMemory(filterExt->ColdResetAtr, sizeof (filterExt->ColdResetAtr));
                }
                if (CompletionParams->Parameters.Ioctl.Output.Length <= sizeof(filterExt->ColdResetAtr))
                {
                    filterExt->ColdResetAtrSize = (UCHAR) CompletionParams->Parameters.Ioctl.Output.Length;
                    WdfMemoryCopyToBuffer(output,
                                          0,
                                          filterExt->ColdResetAtr,
                                          CompletionParams->Parameters.Ioctl.Output.Length);
                }
                break;

            case SCARD_WARM_RESET:
                //
                // Copy the saved ATR.
                //
                if ((filterExt->ColdResetAtrSize != 0) &&
                    (requestParams.Parameters.DeviceIoControl.OutputBufferLength >= filterExt->ColdResetAtrSize))
                {
                    WdfRequestSetInformation(Request, filterExt->ColdResetAtrSize);
                    CompletionParams->Parameters.Ioctl.Output.Length = filterExt->ColdResetAtrSize;
                    CompletionParams->IoStatus.Information = filterExt->ColdResetAtrSize;
                    WdfMemoryCopyFromBuffer(output,
                                            0,
                                            filterExt->ColdResetAtr,
                                            filterExt->ColdResetAtrSize);
                }
                break;

            case SCARD_POWER_DOWN:
                //
                // Clear out the saved ATR.
                //
                if (filterExt->ColdResetAtrSize != 0)
                {
                    filterExt->ColdResetAtrSize = 0;
                    RtlZeroMemory(filterExt->ColdResetAtr, sizeof (filterExt->ColdResetAtr));
                }
                break;

            default:
                status = STATUS_INVALID_DEVICE_REQUEST;
                break;
            }
            
            break;
        }
    }

    WdfRequestComplete(Request, CompletionParams->IoStatus.Status);

    return;
}


