#include "pch.h"
#include "DongleWrapper.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <cstring>

DongleWrapper::DongleWrapper(const std::string& vendorCodeFilePath, const std::string& password)
    : vendorCodeFilePath(vendorCodeFilePath), password(password),
    lastHaspStatus(0), lastLicenseGenStatus(SNTL_LG_STATUS_OK), lastAdminStatus(SNTL_ADMIN_STATUS_OK) {
    if (password.empty()) {
        throw std::runtime_error("Password cannot be empty");
    }
}

DongleWrapper::~DongleWrapper() {
    std::fill(password.begin(), password.end(), 0);
}

bool DongleWrapper::IsValidSession(unsigned long sessionHandle) {
    return sessionHandle != 0;
}

std::string DongleWrapper::LoadAndDecryptVendorCode() {
    std::ifstream file(vendorCodeFilePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open vendor code file");
    }

    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (buffer.size() < 32) {
        throw std::runtime_error("Encrypted file too small");
    }

    const unsigned char* data = buffer.data();
    if (std::memcmp(data, "Salted__", 8) != 0) {
        throw std::runtime_error("Invalid file format: missing Salted__ header");
    }

    const unsigned char* salt = data + 8;
    const unsigned char* iv = data + 16;
    const unsigned char* ciphertext = data + 32;
    size_t ciphertext_len = buffer.size() - 32;

    const int key_len = 32;
    unsigned char key[key_len];
    int iter = 100000;
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, 8, iter, EVP_sha256(), key_len, key) != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create decryption context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<unsigned char> plaintext(ciphertext_len + 16);
    int plaintext_len = 0;
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption update failed");
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

// Error handling methods
unsigned long DongleWrapper::GetLastHaspStatus() const {
    return lastHaspStatus;
}

sntl_lg_status_t DongleWrapper::GetLastLicenseGenStatus() const {
    return lastLicenseGenStatus;
}

sntl_admin_status_t DongleWrapper::GetLastAdminStatus() const {
    return lastAdminStatus;
}

std::string DongleWrapper::GetLastErrorMessage() const {
    if (lastHaspStatus != HASP_STATUS_OK) {
        return GetHaspErrorMessage(lastHaspStatus);
    }
    else if (lastLicenseGenStatus != SNTL_LG_STATUS_OK) {
        return GetLicenseGenErrorMessage(lastLicenseGenStatus);
    }
    else if (lastAdminStatus != SNTL_ADMIN_STATUS_OK) {
        return GetAdminErrorMessage(lastAdminStatus);
    }
    return "No error";
}

std::string DongleWrapper::GetHaspErrorMessage(unsigned long status) const {
    switch (status) {
    case HASP_STATUS_OK: return "Operation successful";
    case HASP_INV_HND: return "Invalid handle";
    case HASP_NO_API_DYLIB: return "Unable to locate the dynamic library for this vendor code";
    case HASP_BROKEN_SESSION: return "Login Session was interrupted";
    case HASP_TMOF: return "Too many open features";
	case HASP_INSUF_MEM: return "Insufficient memory";
    case HASP_DEVICE_ERR: return "Device error";
    case HASP_LOCAL_COMM_ERR: return "Local communication error";
    case HASP_REMOTE_COMM_ERR: return "Remote communication error";
    case HASP_INV_VCODE: return "Invalid vendor code";
    case HASP_FEATURE_NOT_FOUND: return "Feature not found";
    default: return "Unknown HASP error: " + std::to_string(status);
    }
}

std::string DongleWrapper::GetLicenseGenErrorMessage(sntl_lg_status_t status) const {
    switch (status) {
    case SNTL_LG_STATUS_OK: return "Operation successful";
    case SNTL_LG_INVALID_VENDOR_CODE: return "Invalid vendor code";
    case SNTL_LG_INVALID_PARAMETER: return "Invalid parameter";
    case SNTL_LG_OUT_OF_MEMORY: return "No memory available";
    case SNTL_LG_KEY_CURRENT_STATE_MISSING: return "The current state of the key is required in order to generate a license";
    case SNTL_LG_NOTHING_TO_GENERATE: return "There is nothing to be generated as a license";
    default: return "Unknown License Generation error: " + std::to_string(status);
    }
}

std::string DongleWrapper::GetAdminErrorMessage(sntl_admin_status_t status) const {
    switch (status) {
    case SNTL_ADMIN_STATUS_OK: return "Operation successful";
    case SNTL_ADMIN_INVALID_PTR: return "The input parameter is NULL";
    case SNTL_ADMIN_INSUF_MEM: return "Insufficient memory";
    case SNTL_ADMIN_LOCAL_NETWORK_ERR: return "An error occurred while the API was initializing the local network interface";
    case SNTL_ADMIN_INVALID_CONTEXT: return "The License Manager context is corrupt or contains invalid data";
    default: return "Unknown Admin error: " + std::to_string(status);
    }
}

// Licensing API Implementations
DongleError DongleWrapper::LoginToFeature(unsigned int featureId, unsigned long& sessionHandle) {
    try {
        std::string vendorCode = LoadAndDecryptVendorCode();

        hasp_handle_t handle;
        hasp_status_t status = hasp_login(featureId, vendorCode.c_str(), &handle);
        lastHaspStatus = status;
        if (status != HASP_STATUS_OK) {
            return DongleError::LOGIN_FAILED;
        }
        sessionHandle = static_cast<unsigned long>(handle);
        return DongleError::SUCCESS;
    }
    catch (const std::exception&) {
        return DongleError::DECRYPTION_FAILED;
    }
}

DongleError DongleWrapper::Logout(unsigned long sessionHandle) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    hasp_status_t status = hasp_logout(static_cast<hasp_handle_t>(sessionHandle));
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::LOGOUT_FAILED;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::GetInfo(unsigned long sessionHandle, const char* scope, const char* format, char** info) {
    try {
        std::string vendorCode = LoadAndDecryptVendorCode();

        hasp_status_t status = hasp_get_info(scope, format, vendorCode.c_str(), info);
        lastHaspStatus = status;
        if (status != HASP_STATUS_OK) {
            return DongleError::OPERATION_FAILED;
        }
        return DongleError::SUCCESS;
    }
    catch (const std::exception&) {
        return DongleError::DECRYPTION_FAILED;
    }
}

DongleError DongleWrapper::GetSessionInfo(unsigned long sessionHandle, const char* format, char** info) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    hasp_status_t status = hasp_get_sessioninfo(static_cast<hasp_handle_t>(sessionHandle), format, info);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::OPERATION_FAILED;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::UpdateLicense(unsigned long sessionHandle, const char* updateData) {
    hasp_status_t status = hasp_update(updateData, nullptr);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::OPERATION_FAILED;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::TransferLicense(unsigned long sessionHandle, const char* transferData) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    if (!transferData) {
        return DongleError::OPERATION_FAILED;
    }

    char* sessionInfo = nullptr;
    hasp_status_t status = hasp_get_sessioninfo(static_cast<hasp_handle_t>(sessionHandle), HASP_KEYINFO, &sessionInfo);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK || !sessionInfo) {
        return DongleError::OPERATION_FAILED;
    }

    std::string scope = "<haspscope><hasp id=\"*\" /></haspscope>";
    try {
        std::string vendorCode = LoadAndDecryptVendorCode();

        char* info = nullptr;
        status = hasp_transfer(transferData, scope.c_str(), vendorCode.c_str(), nullptr, &info);
        lastHaspStatus = status;

        if (sessionInfo) hasp_free(sessionInfo);
        if (status != HASP_STATUS_OK) {
            if (info) hasp_free(info);
            return DongleError::OPERATION_FAILED;
        }
        if (info) hasp_free(info);
        return DongleError::SUCCESS;
    }
    catch (const std::exception&) {
        if (sessionInfo) hasp_free(sessionInfo);
        return DongleError::DECRYPTION_FAILED;
    }
}

DongleError DongleWrapper::GetMemorySize(unsigned long sessionHandle, unsigned int& size) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    hasp_size_t memorySize;
    hasp_status_t status = hasp_get_size(static_cast<hasp_handle_t>(sessionHandle), 0, &memorySize);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::MEMORY_ERROR;
    }
    size = static_cast<unsigned int>(memorySize);
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::ReadMemory(unsigned long sessionHandle, unsigned int offset, unsigned int length, unsigned char* buffer) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    if (!buffer) {
        return DongleError::MEMORY_ERROR;
    }
    hasp_status_t status = hasp_read(static_cast<hasp_handle_t>(sessionHandle), 0, offset, length, buffer);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::MEMORY_ERROR;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::WriteMemory(unsigned long sessionHandle, unsigned int offset, unsigned int length, const unsigned char* buffer) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    if (!buffer) {
        return DongleError::MEMORY_ERROR;
    }
    hasp_status_t status = hasp_write(static_cast<hasp_handle_t>(sessionHandle), 0, offset, length, buffer);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::MEMORY_ERROR;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::GetRealTimeClock(unsigned long sessionHandle, unsigned long& time) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    hasp_time_t haspTime;
    hasp_status_t status = hasp_get_rtc(static_cast<hasp_handle_t>(sessionHandle), &haspTime);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::TIME_ERROR;
    }
    time = static_cast<unsigned long>(haspTime);
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::EncryptData(unsigned long sessionHandle, const unsigned char* data, unsigned int length, unsigned char* encryptedData) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    if (!data || !encryptedData || length < HASP_MIN_BLOCK_SIZE) {
        return DongleError::ENCRYPTION_ERROR;
    }
    std::memcpy(encryptedData, data, length);
    hasp_status_t status = hasp_encrypt(static_cast<hasp_handle_t>(sessionHandle), encryptedData, length);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::ENCRYPTION_ERROR;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::DecryptData(unsigned long sessionHandle, const unsigned char* encryptedData, unsigned int length, unsigned char* decryptedData) {
    if (!IsValidSession(sessionHandle)) {
        return DongleError::INVALID_SESSION;
    }
    if (!encryptedData || !decryptedData || length < HASP_MIN_BLOCK_SIZE) {
        return DongleError::DECRYPTION_ERROR;
    }
    std::memcpy(decryptedData, encryptedData, length);
    hasp_status_t status = hasp_decrypt(static_cast<hasp_handle_t>(sessionHandle), decryptedData, length);
    lastHaspStatus = status;
    if (status != HASP_STATUS_OK) {
        return DongleError::DECRYPTION_ERROR;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::InitializeLicenseGeneration(unsigned long& lgHandle) {
    try {
        std::string vendorCode = LoadAndDecryptVendorCode();

        sntl_lg_handle_t handle;
        sntl_lg_status_t status = sntl_lg_initialize(vendorCode.c_str(), &handle);
        lastLicenseGenStatus = status;
        if (status != SNTL_LG_STATUS_OK) {
            return DongleError::LICENSE_GENERATION_FAILED;
        }
        lgHandle = static_cast<unsigned long>(handle);
        return DongleError::SUCCESS;
    }
    catch (const std::exception&) {
        return DongleError::DECRYPTION_FAILED;
    }
}

DongleError DongleWrapper::CleanupLicenseGeneration(unsigned long& lgHandle) {
    if (!lgHandle) {
        return DongleError::INVALID_SESSION;
    }
    sntl_lg_status_t status = sntl_lg_cleanup(&lgHandle);
    lastLicenseGenStatus = status;
    if (status != SNTL_LG_STATUS_OK) {
        return DongleError::LICENSE_GENERATION_FAILED;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::StartLicenseGeneration(unsigned long lgHandle, const char* keyId, const char* licenseDefinition) {
    if (!lgHandle) {
        return DongleError::INVALID_SESSION;
    }
    try {
        std::string vendorCode = LoadAndDecryptVendorCode();

        sntl_lg_status_t status = sntl_lg_start(static_cast<sntl_lg_handle_t>(lgHandle), nullptr, vendorCode.c_str(),
            SNTL_LG_LICENSE_TYPE_UPDATE, licenseDefinition, keyId);
        lastLicenseGenStatus = status;
        if (status != SNTL_LG_STATUS_OK) {
            return DongleError::LICENSE_GENERATION_FAILED;
        }
        return DongleError::SUCCESS;
    }
    catch (const std::exception&) {
        return DongleError::DECRYPTION_FAILED;
    }
}

DongleError DongleWrapper::ApplyLicenseTemplate(unsigned long lgHandle, const char* templateData) {
    if (!lgHandle) {
        return DongleError::INVALID_SESSION;
    }
    sntl_lg_status_t status = sntl_lg_apply_template(static_cast<sntl_lg_handle_t>(lgHandle), templateData);
    lastLicenseGenStatus = status;
    if (status != SNTL_LG_STATUS_OK) {
        return DongleError::LICENSE_GENERATION_FAILED;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::GenerateLicense(unsigned long lgHandle, char** licenseData) {
    if (!lgHandle || !licenseData) {
        return DongleError::INVALID_PARAMETER;
    }
    sntl_lg_status_t status = sntl_lg_generate_license(static_cast<sntl_lg_handle_t>(lgHandle), nullptr, licenseData, nullptr);
    lastLicenseGenStatus = status;
    if (status != SNTL_LG_STATUS_OK) {
        return DongleError::LICENSE_GENERATION_FAILED;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::DecodeCurrentState(unsigned long lgHandle, const char* currentState, char** stateData) {
    if (!lgHandle || !stateData) {
        return DongleError::INVALID_PARAMETER;
    }
    try {
        std::string vendorCode = LoadAndDecryptVendorCode();

        sntl_lg_status_t status = sntl_lg_decode_current_state(static_cast<sntl_lg_handle_t>(lgHandle), vendorCode.c_str(),
            currentState, stateData);
        lastLicenseGenStatus = status;
        if (status != SNTL_LG_STATUS_OK) {
            return DongleError::LICENSE_GENERATION_FAILED;
        }
        return DongleError::SUCCESS;
    }
    catch (const std::exception&) {
        return DongleError::DECRYPTION_FAILED;
    }
}

DongleError DongleWrapper::GetLicenseGenerationInfo(unsigned long lgHandle, sntl_lg_info_type_t infoType, char** info) {
    if (!lgHandle || !info) {
        return DongleError::INVALID_PARAMETER;
    }
    sntl_lg_status_t status = sntl_lg_get_info(static_cast<sntl_lg_handle_t>(lgHandle), infoType, info);
    lastLicenseGenStatus = status;
    if (status != SNTL_LG_STATUS_OK) {
        return DongleError::LICENSE_GENERATION_FAILED;
    }
    return DongleError::SUCCESS;
}

DongleError DongleWrapper::CreateAdminContext(sntl_admin_context_t** adminHandle) {
    if (!adminHandle) {
        return DongleError::INVALID_PARAMETER;
    }
    sntl_admin_status_t status = sntl_admin_context_new(adminHandle, "localhost", 0, nullptr);
    lastAdminStatus = status;
    return (status == SNTL_ADMIN_STATUS_OK) ? DongleError::SUCCESS : DongleError::ADMIN_OPERATION_FAILED;
}

DongleError DongleWrapper::DeleteAdminContext(sntl_admin_context_t* adminHandle) {
    if (!adminHandle) {
        return DongleError::INVALID_SESSION;
    }
    sntl_admin_status_t status = sntl_admin_context_delete(adminHandle);
    lastAdminStatus = status;
    return (status == SNTL_ADMIN_STATUS_OK) ? DongleError::SUCCESS : DongleError::ADMIN_OPERATION_FAILED;
}

DongleError DongleWrapper::GetAdminInfo(sntl_admin_context_t* adminHandle, const char* scope, char** info) {
    if (!adminHandle || !scope || !info) {
        return DongleError::INVALID_PARAMETER;
    }
    const char* format = "<haspformat format=\"default\"/>";
    sntl_admin_status_t status = sntl_admin_get(adminHandle, scope, format, info);
    lastAdminStatus = status;
    return (status == SNTL_ADMIN_STATUS_OK) ? DongleError::SUCCESS : DongleError::ADMIN_OPERATION_FAILED;
}

DongleError DongleWrapper::SetAdminConfig(sntl_admin_context_t* adminHandle, const char* configData) {
    if (!adminHandle || !configData) {
        return DongleError::INVALID_PARAMETER;
    }
    char* statusInfo = nullptr;
    sntl_admin_status_t status = sntl_admin_set(adminHandle, configData, &statusInfo);
    lastAdminStatus = status;
    if (statusInfo) sntl_admin_free(statusInfo);
    return (status == SNTL_ADMIN_STATUS_OK) ? DongleError::SUCCESS : DongleError::ADMIN_OPERATION_FAILED;
}