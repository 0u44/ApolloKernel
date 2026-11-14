#ifndef APOLLO_ROULETTE_H
#define APOLLO_ROULETTE_H

#include "types.h"

#define ROULETTE_NUMBERS 38  // 0, 00, 1-36
#define ROULETTE_MAX_BET_SPOTS 20
#define ROULETTE_STARTING_CHIPS 1000
#define ROULETTE_MIN_BET 5
#define ROULETTE_MAX_BET 500

typedef enum {
    ROULETTE_BET_STRAIGHT = 0,    // Single number (35:1)
    ROULETTE_BET_RED = 1,         // Red (1:1)
    ROULETTE_BET_BLACK = 2,       // Black (1:1)
    ROULETTE_BET_ODD = 3,         // Odd (1:1)
    ROULETTE_BET_EVEN = 4,        // Even (1:1)
    ROULETTE_BET_HIGH = 5,        // 19-36 (1:1)
    ROULETTE_BET_LOW = 6,         // 1-18 (1:1)
    ROULETTE_BET_DOZEN1 = 7,      // 1-12 (2:1)
    ROULETTE_BET_DOZEN2 = 8,      // 13-24 (2:1)
    ROULETTE_BET_DOZEN3 = 9,      // 25-36 (2:1)
} roulette_bet_type_t;

typedef struct {
    roulette_bet_type_t type;
    int32_t number;      // For straight bets
    int32_t amount;
    bool active;
} roulette_bet_t;

typedef enum {
    ROULETTE_STATE_BETTING = 0,
    ROULETTE_STATE_SPINNING = 1,
    ROULETTE_STATE_RESULT = 2,
    ROULETTE_STATE_EXIT = 3
} roulette_game_state_t;

typedef struct {
    int32_t player_chips;
    int32_t current_bet_amount;
    
    roulette_bet_t bets[ROULETTE_MAX_BET_SPOTS];
    uint32_t bet_count;
    
    int32_t winning_number;
    int32_t total_bet;
    int32_t total_won;
    
    roulette_game_state_t game_state;
    
    uint32_t round_number;
    uint32_t total_spins;
    int32_t total_winnings;
    
    int32_t selected_bet_type;
    int32_t selected_number;
    
    bool needs_redraw;
} roulette_game_t;

void roulette_initialize(roulette_game_t* game);
void roulette_run(roulette_game_t* game);
void roulette_render(roulette_game_t* game);
void roulette_handle_input(roulette_game_t* game, uint8_t key);

#endif