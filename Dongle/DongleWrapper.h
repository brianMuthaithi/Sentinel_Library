#ifdef DONGLEWRAPPER_EXPORTS
#define DONGLEWRAPPER_API __declspec(dllexport)
#else
#define DONGLEWRAPPER_API __declspec(dllimport)
#endif
#include "sntl_adminapi.h"
#include "sntl_licgen.h"
#include "hasp_api.h"
#include <string>

enum class DongleError {
    SUCCESS = 0,
    LOGIN_FAILED,
    LOGOUT_FAILED,
    INVALID_SESSION,
    INVALID_PARAMETER,
    OPERATION_FAILED,
    MEMORY_ERROR,
    TIME_ERROR,
    ENCRYPTION_ERROR,
    DECRYPTION_ERROR,
    LICENSE_GENERATION_FAILED,
    ADMIN_OPERATION_FAILED,
    DECRYPTION_FAILED
};

class DONGLEWRAPPER_API DongleWrapper {
public:
    DongleWrapper(const std::string& vendorCodeFilePath, const std::string& password);
    ~DongleWrapper();

    bool IsValidSession(unsigned long sessionHandle);

    // Licensing API Functions
    DongleError LoginToFeature(unsigned int featureId, unsigned long& sessionHandle);
    DongleError Logout(unsigned long sessionHandle);
    DongleError GetInfo(unsigned long sessionHandle, const char* scope, const char* format, char** info);
    DongleError GetSessionInfo(unsigned long sessionHandle, const char* format, char** info);
    DongleError UpdateLicense(unsigned long sessionHandle, const char* updateData);
    DongleError TransferLicense(unsigned long sessionHandle, const char* transferData);
    DongleError GetMemorySize(unsigned long sessionHandle, unsigned int& size);
    DongleError ReadMemory(unsigned long sessionHandle, unsigned int offset, unsigned int length, unsigned char* buffer);
    DongleError WriteMemory(unsigned long sessionHandle, unsigned int offset, unsigned int length, const unsigned char* buffer);
    DongleError GetRealTimeClock(unsigned long sessionHandle, unsigned long& time);
    DongleError EncryptData(unsigned long sessionHandle, const unsigned char* data, unsigned int length, unsigned char* encryptedData);
    DongleError DecryptData(unsigned long sessionHandle, const unsigned char* encryptedData, unsigned int length, unsigned char* decryptedData);

    // License Generation API Functions
    DongleError InitializeLicenseGeneration(unsigned long& lgHandle);
    DongleError CleanupLicenseGeneration(unsigned long& lgHandle);
    DongleError StartLicenseGeneration(unsigned long lgHandle, const char* keyId, const char* licenseDefinition);
    DongleError ApplyLicenseTemplate(unsigned long lgHandle, const char* templateData);
    DongleError GenerateLicense(unsigned long lgHandle, char** licenseData);
    DongleError DecodeCurrentState(unsigned long lgHandle, const char* currentState, char** stateData);
    DongleError SNTL_LG_CALLCONV GetLicenseGenerationInfo(unsigned long lgHandle, sntl_lg_info_type_t infoType, char** info);

    // Admin API Functions
    DongleError SNTL_ADMIN_CALLCONV CreateAdminContext(sntl_admin_context_t** adminHandle);
    DongleError SNTL_ADMIN_CALLCONV DeleteAdminContext(sntl_admin_context_t* adminHandle);
    DongleError SNTL_ADMIN_CALLCONV GetAdminInfo(sntl_admin_context_t* adminHandle, const char* scope, char** info);
    DongleError SNTL_ADMIN_CALLCONV SetAdminConfig(sntl_admin_context_t* adminHandle, const char* configData);

    // Error handling methods
    unsigned long GetLastHaspStatus() const; // For HASP API status codes
    sntl_lg_status_t GetLastLicenseGenStatus() const; // For License Generation API status codes
    sntl_admin_status_t GetLastAdminStatus() const; // For Admin API status codes
    std::string GetLastErrorMessage() const; // Get the human-readable error message

private:
    std::string vendorCodeFilePath;
    std::string password;
    std::string LoadAndDecryptVendorCode();

    // Store the last status codes for each API
    unsigned long lastHaspStatus; // For HASP API
    sntl_lg_status_t lastLicenseGenStatus; // For License Generation API
    sntl_admin_status_t lastAdminStatus; // For Admin API

    // Helper method to map status codes to error messages
    std::string GetHaspErrorMessage(unsigned long status) const;
    std::string GetLicenseGenErrorMessage(sntl_lg_status_t status) const;
    std::string GetAdminErrorMessage(sntl_admin_status_t status) const;
};