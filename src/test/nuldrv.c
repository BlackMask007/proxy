/*
 * nuldrv.c — 最小驱动装载探针(诊断用):仅创建设备+符号链接,无 WFP。
 * 用于区分"环境装不上任何驱动"与"本项目驱动镜像问题"。
 */
#include <ntddk.h>

/* 诊断:强制保留 fwpkclnt/NDIS 导入(与 hpxdrv 相同的导入面),验证装载差异是否源于导入 */
__declspec(dllimport) NTSTATUS NTAPI FwpsCalloutRegister1(void* dev, const void* callout, unsigned int* id);
__declspec(dllimport) void* NTAPI NdisAllocateNetBufferListPool(void* hdr, const void* params);
volatile PVOID g_ForceImports[2] = { (PVOID)FwpsCalloutRegister1, (PVOID)NdisAllocateNetBufferListPool };

static void NulUnload(PDRIVER_OBJECT drv)
{
    UNICODE_STRING dosName;
    RtlInitUnicodeString(&dosName, L"\\??\\HpxNul");
    IoDeleteSymbolicLink(&dosName);
    if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regPath)
{
    UNICODE_STRING devName, dosName;
    PDEVICE_OBJECT dev = NULL;
    NTSTATUS st;
    UNREFERENCED_PARAMETER(regPath);
    RtlInitUnicodeString(&devName, L"\\Device\\HpxNul");
    st = IoCreateDevice(drv, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    RtlInitUnicodeString(&dosName, L"\\??\\HpxNul");
    st = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(dev);
        return st;
    }
    drv->DriverUnload = NulUnload;
    return STATUS_SUCCESS;
}
