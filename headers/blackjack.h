#ifndef APOLLO_BLACKJACK_H
#define APOLLO_BLACKJACK_H

#include "types.h"

#define DECK_SIZE 52
#define MAX_CARDS_IN_HAND 12
#define BLACKJACK_STARTING_CHIPS 1000
#define BLACKJACK_MIN_BET 10
#define BLACKJACK_MAX_BET 500

typedef enum {
    BLACKJACK_STATE_BETTING = 0,
    BLACKJACK_STATE_PLAYER_TURN = 1,
    BLACKJACK_STATE_DEALER_TURN = 2,
    BLACKJACK_STATE_ROUND_OVER = 3,
    BLACKJACK_STATE_EXIT = 4
} blackjack_game_state_t;

typedef struct {
    uint8_t deck[DECK_SIZE];
    uint32_t deck_position;
    
    uint8_t dealer_cards[MAX_CARDS_IN_HAND];
    uint8_t player_cards[MAX_CARDS_IN_HAND];
    uint32_t dealer_card_count;
    uint32_t player_card_count;
    
    int32_t dealer_score;
    int32_t player_score;
    
    int32_t player_chips;
    int32_t current_bet;
    
    blackjack_game_state_t game_state;
    
    uint32_t round_number;
    uint32_t wins;
    uint32_t losses;
    uint32_t pushes;
    
    bool needs_redraw;
} blackjack_game_t;

void blackjack_initialize(blackjack_game_t* game);
void blackjack_run(blackjack_game_t* game);
void blackjack_render(blackjack_game_t* game);
void blackjack_handle_input(blackjack_game_t* game, uint8_t key);

#endif