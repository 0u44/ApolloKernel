#include "blackjack.h"
#include "terminal.h"
#include "input_manager.h"
#include "types.h"

#ifndef SCANCODE_ESCAPE
#define SCANCODE_ESCAPE 0x01
#endif

static void dealer_play(blackjack_game_t* game);

static uint8_t wait_for_key(void) {
    while (input_manager_has_input()) {
        input_manager_read_scancode();
    }
    
    while (!input_manager_has_input()) {
        __asm__ volatile("pause");
    }
    
    uint8_t scancode = input_manager_read_scancode();
    char ascii = input_manager_scancode_to_ascii(scancode);
    
    // Return ASCII if available, otherwise return scancode for special keys
    return ascii != 0 ? ascii : scancode;
}

static void shuffle_deck(blackjack_game_t* game) {
    // Initialize deck (0-51 representing all cards)
    for (uint32_t i = 0; i < DECK_SIZE; i++) {
        game->deck[i] = i;
    }
    
    // Fisher-Yates shuffle with simple PRNG
    uint32_t seed = game->round_number * 1103515245 + 12345;
    for (int32_t i = DECK_SIZE - 1; i > 0; i--) {
        seed = seed * 1103515245 + 12345;
        int32_t j = (seed / 65536) % (i + 1);
        uint8_t temp = game->deck[i];
        game->deck[i] = game->deck[j];
        game->deck[j] = temp;
    }
    
    game->deck_position = 0;
}

static uint8_t deal_card(blackjack_game_t* game) {
    if (game->deck_position >= DECK_SIZE) {
        shuffle_deck(game);
    }
    return game->deck[game->deck_position++];
}

static int32_t get_card_rank(uint8_t card) {
    return (card % 13) + 1;
}

static char get_card_suit_char(uint8_t card) {
    uint8_t suit = card / 13;
    switch (suit) {
        case 0: return 'H';
        case 1: return 'D';
        case 2: return 'C';
        case 3: return 'S';
        default: return '?';
    }
}

static char get_card_rank_char(uint8_t card) {
    int32_t rank = get_card_rank(card);
    switch (rank) {
        case 1: return 'A';
        case 10: return 'T';
        case 11: return 'J';
        case 12: return 'Q';
        case 13: return 'K';
        default: return '0' + rank;
    }
}

static int32_t calculate_score(uint8_t* cards, uint32_t count) {
    int32_t score = 0;
    int32_t aces = 0;
    
    for (uint32_t i = 0; i < count; i++) {
        int32_t rank = get_card_rank(cards[i]);
        if (rank == 1) {
            aces++;
            score += 11;
        } else if (rank > 10) {
            score += 10;
        } else {
            score += rank;
        }
    }
    
    while (score > 21 && aces > 0) {
        score -= 10;
        aces--;
    }
    
    return score;
}

static void draw_card_visual(uint8_t card) {
    char rank = get_card_rank_char(card);
    char suit = get_card_suit_char(card);
    
    terminal_write_string(" +");
    terminal_write_char(rank);
    terminal_write_char(suit);
    terminal_write_string("+ ");
}

static void draw_separator(void) {
    terminal_write_string("\n");
    for (int i = 0; i < 70; i++) {
        terminal_write_char('=');
    }
    terminal_write_string("\n");
}

static void start_new_round(blackjack_game_t* game) {
    if (game->player_chips < game->current_bet) {
        game->game_state = BLACKJACK_STATE_BETTING;
        game->needs_redraw = true;
        return;
    }
    
    if (game->player_chips <= 0) {
        game->game_state = BLACKJACK_STATE_EXIT;
        game->needs_redraw = true;
        return;
    }
    
    game->round_number++;
    game->player_chips -= game->current_bet;
    
    game->dealer_card_count = 0;
    game->player_card_count = 0;
    
    game->player_cards[game->player_card_count++] = deal_card(game);
    game->dealer_cards[game->dealer_card_count++] = deal_card(game);
    game->player_cards[game->player_card_count++] = deal_card(game);
    game->dealer_cards[game->dealer_card_count++] = deal_card(game);
    
    game->player_score = calculate_score(game->player_cards, game->player_card_count);
    game->dealer_score = calculate_score(game->dealer_cards, game->dealer_card_count);
    
    if (game->player_score == 21) {
        game->player_chips += (game->current_bet * 5) / 2;
        game->wins++;
        game->game_state = BLACKJACK_STATE_ROUND_OVER;
    } else {
        game->game_state = BLACKJACK_STATE_PLAYER_TURN;
    }
    
    game->needs_redraw = true;
}

static void player_hit(blackjack_game_t* game) {
    if (game->game_state != BLACKJACK_STATE_PLAYER_TURN) return;
    if (game->player_card_count >= MAX_CARDS_IN_HAND) return;
    
    game->player_cards[game->player_card_count++] = deal_card(game);
    game->player_score = calculate_score(game->player_cards, game->player_card_count);
    
    if (game->player_score > 21) {
        game->losses++;
        game->game_state = BLACKJACK_STATE_ROUND_OVER;
    } else if (game->player_score == 21) {
        dealer_play(game);
    }
    
    game->needs_redraw = true;
}

static void dealer_play(blackjack_game_t* game) {
    game->game_state = BLACKJACK_STATE_DEALER_TURN;
    game->needs_redraw = true;
    
    while (game->dealer_score < 17) {
        if (game->dealer_card_count >= MAX_CARDS_IN_HAND) break;
        game->dealer_cards[game->dealer_card_count++] = deal_card(game);
        game->dealer_score = calculate_score(game->dealer_cards, game->dealer_card_count);
    }
    
    if (game->dealer_score > 21) {
        game->player_chips += game->current_bet * 2;
        game->wins++;
    } else if (game->player_score > game->dealer_score) {
        game->player_chips += game->current_bet * 2;
        game->wins++;
    } else if (game->player_score < game->dealer_score) {
        game->losses++;
    } else {
        game->player_chips += game->current_bet;
        game->pushes++;
    }
    
    game->game_state = BLACKJACK_STATE_ROUND_OVER;
    game->needs_redraw = true;
}

static void player_stay(blackjack_game_t* game) {
    if (game->game_state != BLACKJACK_STATE_PLAYER_TURN) return;
    dealer_play(game);
}

void blackjack_initialize(blackjack_game_t* game) {
    game->player_chips = BLACKJACK_STARTING_CHIPS;
    game->current_bet = BLACKJACK_MIN_BET;
    game->game_state = BLACKJACK_STATE_BETTING;
    game->round_number = 0;
    game->wins = 0;
    game->losses = 0;
    game->pushes = 0;
    game->needs_redraw = true;
    game->dealer_card_count = 0;
    game->player_card_count = 0;
    game->deck_position = 0;
    
    shuffle_deck(game);
}

void blackjack_render(blackjack_game_t* game) {
    if (!game->needs_redraw) return;
    
    terminal_clear();
    
    draw_separator();
    terminal_set_color(14, 0);
    terminal_write_string("          APOLLO BLACKJACK CASINO v0.4 (cn ~ Alpha)\n");
    terminal_set_color(7, 0);
    
    if (game->round_number > 0) {
        terminal_write_string("                Round ");
        terminal_write_uint(game->round_number);
        terminal_write_string("\n");
    }
    draw_separator();
    
    if (game->game_state == BLACKJACK_STATE_EXIT) {
        terminal_set_color(12, 0);
        terminal_write_string("\n       GAME OVER - You're out of chips!\n\n");
        terminal_set_color(7, 0);
        terminal_write_string("       Final Stats:\n");
        terminal_write_string("         Wins: ");
        terminal_write_uint(game->wins);
        terminal_write_string("  Losses: ");
        terminal_write_uint(game->losses);
        terminal_write_string("  Pushes: ");
        terminal_write_uint(game->pushes);
        terminal_write_string("\n\n       Press Ctrl+ESC to exit\n");
        draw_separator();
        game->needs_redraw = false;
        return;
    }
    
    if (game->game_state == BLACKJACK_STATE_BETTING) {
        terminal_write_string("\n");
        terminal_set_color(11, 0);
        terminal_write_string("  Chips: $");
        terminal_write_uint(game->player_chips);
        terminal_set_color(7, 0);
        terminal_write_string("  |  ");
        terminal_set_color(14, 0);
        terminal_write_string("Current Bet: $");
        terminal_write_uint(game->current_bet);
        terminal_set_color(7, 0);
        terminal_write_string("\n\n");
        
        terminal_write_string("  Min Bet: $");
        terminal_write_uint(BLACKJACK_MIN_BET);
        terminal_write_string("  |  Max Bet: $");
        terminal_write_uint(BLACKJACK_MAX_BET);
        terminal_write_string("\n\n");
        
        terminal_write_string("  [ +/- ] Adjust Bet  [ Ctrl+/- ] Max/Min\n");
        terminal_write_string("  [ SPACE ] Deal Cards  [ Ctrl+ESC ] Exit\n\n");
        
        terminal_write_string("  Stats - W:");
        terminal_write_uint(game->wins);
        terminal_write_string(" L:");
        terminal_write_uint(game->losses);
        terminal_write_string(" P:");
        terminal_write_uint(game->pushes);
        terminal_write_string("\n");
        
        draw_separator();
        game->needs_redraw = false;
        return;
    }
    
    terminal_write_string("\n");
    terminal_set_color(12, 0);
    terminal_write_string("DEALER: ");
    terminal_set_color(7, 0);
    
    if (game->game_state == BLACKJACK_STATE_PLAYER_TURN) {
        terminal_write_string(" [***] ");
        draw_card_visual(game->dealer_cards[0]);
        terminal_write_string("   [??]\n");
    } else {
        for (uint32_t i = 0; i < game->dealer_card_count; i++) {
            draw_card_visual(game->dealer_cards[i]);
        }
        terminal_write_string("  [");
        terminal_write_uint(game->dealer_score);
        terminal_write_string("]\n");
    }
    
    terminal_write_string("\n");
    terminal_set_color(10, 0);
    terminal_write_string("PLAYER: ");
    terminal_set_color(7, 0);
    for (uint32_t i = 0; i < game->player_card_count; i++) {
        draw_card_visual(game->player_cards[i]);
    }
    terminal_write_string("  [");
    terminal_write_uint(game->player_score);
    terminal_write_string("]\n\n");
    
    terminal_set_color(11, 0);
    terminal_write_string("Chips: $");
    terminal_write_uint(game->player_chips);
    terminal_set_color(7, 0);
    terminal_write_string("  |  Bet: $");
    terminal_write_uint(game->current_bet);
    terminal_write_string("  |  W:");
    terminal_write_uint(game->wins);
    terminal_write_string(" L:");
    terminal_write_uint(game->losses);
    terminal_write_string(" P:");
    terminal_write_uint(game->pushes);
    terminal_write_string("\n");
    
    draw_separator();
    
    if (game->game_state == BLACKJACK_STATE_PLAYER_TURN) {
        terminal_write_string("  [ H ] Hit  [ S ] Stay\n");
        if (game->player_score == 21) {
            terminal_set_color(10, 0);
            terminal_write_string("  BLACKJACK!\n");
            terminal_set_color(7, 0);
        }
        if (game->player_score > 21) {
            terminal_set_color(12, 0);
            terminal_write_string("  BUST!\n");
            terminal_set_color(7, 0);
        }
    } else if (game->game_state == BLACKJACK_STATE_DEALER_TURN) {
        terminal_set_color(14, 0);
        terminal_write_string("  Dealer is playing...\n");
        terminal_set_color(7, 0);
    } else if (game->game_state == BLACKJACK_STATE_ROUND_OVER) {
        terminal_write_string("\n");
        if (game->dealer_score > 21) {
            terminal_set_color(10, 0);
            terminal_write_string("  DEALER BUSTS! You WIN $");
            terminal_write_uint(game->current_bet);
            terminal_write_string("!\n");
        } else if (game->player_score > 21) {
            terminal_set_color(12, 0);
            terminal_write_string("  BUST! You LOSE $");
            terminal_write_uint(game->current_bet);
            terminal_write_string("\n");
        } else if (game->player_score > game->dealer_score) {
            terminal_set_color(10, 0);
            terminal_write_string("  YOU WIN $");
            terminal_write_uint(game->current_bet);
            terminal_write_string("!\n");
        } else if (game->player_score < game->dealer_score) {
            terminal_set_color(12, 0);
            terminal_write_string("  You LOSE $");
            terminal_write_uint(game->current_bet);
            terminal_write_string("\n");
        } else {
            terminal_set_color(14, 0);
            terminal_write_string("  PUSH - Bet Returned\n");
        }
        terminal_set_color(7, 0);
        terminal_write_string("\n  [ SPACE ] Next Hand  [ ESC ] Quit\n");
    }
    
    draw_separator();
    game->needs_redraw = false;
}

void blackjack_handle_input(blackjack_game_t* game, uint8_t key) {
    bool ctrl = input_manager_is_ctrl_pressed();
    
    // Ctrl+ESC to exit
    if (key == SCANCODE_ESCAPE && ctrl) {
        game->game_state = BLACKJACK_STATE_EXIT;
        game->needs_redraw = true;
        return;
    }
    
    switch (game->game_state) {
        case BLACKJACK_STATE_BETTING:
            if (key == '\n' || key == ' ') {
                start_new_round(game);
            } else if (key == '+' || key == '=') {
                if (ctrl) {
                    // Ctrl+Plus = Max bet
                    game->current_bet = (game->player_chips > BLACKJACK_MAX_BET) ? BLACKJACK_MAX_BET : game->player_chips;
                } else {
                    if (game->current_bet < BLACKJACK_MAX_BET && game->current_bet < game->player_chips) {
                        game->current_bet += 10;
                        if (game->current_bet > game->player_chips) {
                            game->current_bet = game->player_chips;
                        }
                    }
                }
                game->needs_redraw = true;
            } else if (key == '-' || key == '_') {
                if (ctrl) {
                    // Ctrl+Minus = Min bet
                    game->current_bet = BLACKJACK_MIN_BET;
                } else {
                    if (game->current_bet > BLACKJACK_MIN_BET) {
                        game->current_bet -= 10;
                        if (game->current_bet < BLACKJACK_MIN_BET) {
                            game->current_bet = BLACKJACK_MIN_BET;
                        }
                    }
                }
                game->needs_redraw = true;
            }
            break;
            
        case BLACKJACK_STATE_PLAYER_TURN:
            if (key == 'h' || key == 'H') {
                player_hit(game);
            } else if (key == 's' || key == 'S') {
                player_stay(game);
            }
            break;
            
        case BLACKJACK_STATE_ROUND_OVER:
            if (key == '\n' || key == ' ') {
                game->game_state = BLACKJACK_STATE_BETTING;
                game->needs_redraw = true;
            }
            break;
            
        default:
            break;
    }
}

void blackjack_run(blackjack_game_t* game) {
    blackjack_initialize(game);
    
    terminal_clear();
    terminal_set_color(7, 0);
    
    draw_separator();
    terminal_set_color(14, 0);
    terminal_write_string("\n       APOLLO BLACKJACK CASINO\n\n");
    terminal_set_color(7, 0);
    terminal_write_string("       Welcome to the high-stakes table!\n");
    terminal_write_string("       Starting chips: $");
    terminal_write_uint(BLACKJACK_STARTING_CHIPS);
    terminal_write_string("\n\n");
    terminal_write_string("       Rules:\n");
    terminal_write_string("         - Get closer to 21 than dealer\n");
    terminal_write_string("         - Dealer hits on 16, stays on 17\n");
    terminal_write_string("         - Blackjack pays 2.5:1\n");
    terminal_write_string("         - Face cards worth 10\n");
    terminal_write_string("         - Aces worth 1 or 11\n\n");
    terminal_write_string("       Press any key to begin...\n");
    draw_separator();
    
    wait_for_key();
    
    while (game->game_state != BLACKJACK_STATE_EXIT) {
        blackjack_render(game);
        
        uint8_t key = wait_for_key();
        blackjack_handle_input(game, key);
    }
    
    blackjack_render(game);
    wait_for_key();
}