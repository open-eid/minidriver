/*++
Copyright (c) 1997  Microsoft Corporation

Module Name:

    atrfilter.h

Abstract:

    This module contains the common private declarations for the ATR filter

Environment:

    kernel mode only

--*/

#ifndef ATRFILTER_H
#define ATRFILTER_H


#pragma warning(disable:4201)

#include "ntddk.h"
#include <winsmcrd.h>

#pragma warning(default:4201)

#include <wdf.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#include <initguid.h>
#include <devguid.h>


#if DBG

#define TRAP()                      DbgBreakPoint()

#define DebugPrint(_x_) DbgPrint _x_

#else   // DBG

#define TRAP()

#define DebugPrint(_x_)

#endif

#define MIN(_A_,_B_) (((_A_) < (_B_)) ? (_A_) : (_B_))

#define ATR_BUFFER_SIZE 64

typedef struct _DEVICE_EXTENSION
{
    WDFDEVICE WdfDevice;

    //
    // Cold reset ATR string and length.
    //
    UCHAR ColdResetAtr[ATR_BUFFER_SIZE];
    UCHAR ColdResetAtrSize;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_EXTENSION,
                                        FilterGetData)

#if VISTA_WDK
//
// Needed for Vista WDK
//
typedef
NTSTATUS
(EVT_WDF_DRIVER_DEVICE_ADD)(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    );

typedef EVT_WDF_DRIVER_DEVICE_ADD *PFN_WDF_DRIVER_DEVICE_ADD;

typedef
VOID
(EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL) (
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t         OutputBufferLength,
    IN size_t         InputBufferLength,
    IN ULONG         IoControlCode
    );

typedef EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL *PFN_WDF_IO_QUEUE_IO_DEVICE_CONTROL;

typedef
VOID
(EVT_WDF_REQUEST_COMPLETION_ROUTINE)(
    IN WDFREQUEST Request,
    IN WDFIOTARGET Target,
    IN PWDF_REQUEST_COMPLETION_PARAMS Params,
    IN WDFCONTEXT Context
    );

typedef EVT_WDF_REQUEST_COMPLETION_ROUTINE *PFN_WDF_REQUEST_COMPLETION_ROUTINE;

#endif // VISTA_WDK

//
// Prototypes
//
DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_DEVICE_ADD AtrFilter_EvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL AtrFilter_EvtIoDeviceControl;

EVT_WDF_REQUEST_COMPLETION_ROUTINE
AtrFilterRequestCompletionRoutine;

#endif  // ATRFILTER_H


