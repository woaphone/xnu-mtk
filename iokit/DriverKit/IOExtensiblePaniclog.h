/*
 * Linux port: kernel-side dispatch declarations for IOExtensiblePaniclog.
 *
 * The class is newer than the macOS 11.3 SDK's IIG output, so its method table
 * macros are written from IOExtensiblePaniclog.iig. Only the _Impl methods the
 * kernel implementation defines are declared; the public DriverKit wrappers are
 * not used by kernel code.
 */
#ifndef _LINUX_DK_IOEXTENSIBLEPANICLOG_H
#define _LINUX_DK_IOEXTENSIBLEPANICLOG_H

class OSData;
class OSString;

#define IOExtensiblePaniclog_Methods

#define IOExtensiblePaniclog_KernelMethods                              \
protected:                                                              \
	static kern_return_t                                            \
	Create_Impl(OSData * uuid, OSString * data_id, uint32_t max_len, \
	    uint32_t options, IOExtensiblePaniclog ** out);              \
	kern_return_t SetActive_Impl(void);                              \
	kern_return_t SetInactive_Impl(void);                            \
	kern_return_t InsertData_Impl(OSData * data);                    \
	kern_return_t AppendData_Impl(OSData * data);                    \
	kern_return_t CopyMemoryDescriptor_Impl(IOBufferMemoryDescriptor ** mem); \
	kern_return_t SetUsedLen_Impl(uint32_t used_len);

#endif
