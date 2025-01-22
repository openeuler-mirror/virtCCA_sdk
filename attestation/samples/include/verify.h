#ifndef VERIFY_H
#define VERIFY_H

#include <stdbool.h>
#include "rem.h"
#include "vcca_event_log.h"
#include "vcca_firmware_state.h"

/* Internal function declarations */
bool read_token_rem(rem_t rems[REM_COUNT]);
void verify_single_rem(int rem_index, const rem_t* rem1, const rem_t* rem2);

/**
 * @brief Verify firmware state hash values
 *
 * @param json_file JSON file path
 * @param state Firmware state
 * @return true Verification successful
 * @return false Verification failed
 */
bool verify_firmware_state(const char* json_file, const vcca_firmware_log_state_t* state);

/**
 * @brief Verifying REM Values
 *
 * This function performs the following steps:
 * 1. Read the CCEL file
 * 2. Obtain the event log area information
 * 3. Initialize the event log processor
 * 4. Replay the event log and calculate the REM value
 * 5. Read the REM value in the token
 * 6. Verify that the calculated REM value is consistent with the value in the token
 *
 * @return true Verification succeeded.
 * @return false Verification failed.
 */
bool verify_rem(void);

#endif /* VERIFY_H */