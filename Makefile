CFLAGS := -Wall -O3 -std=gnu11
DEBUGFLAGS := -Wall -std=gnu11 -g #-fsanitize=address
CC := gcc

source_dir := src
header_dir := headers
build_dir := build
apps_dir := apps
debug_build_dir := build-debug
debug_dir := debug

#Source and object files are automatically found.
source_files := $(shell find $(source_dir) -name '*.c')
header_files := $(shell find $(header_dir) -name '*.h')
object_files := $(patsubst $(source_dir)/%.c,$(build_dir)/%.o,$(source_files))
debug_object_files := $(patsubst $(source_dir)/%.c,$(debug_build_dir)/%.o,$(source_files))

#Creates separate object lists for each executable via a filter on the name
filter_out_stage = $(patsubst $(dir $(firstword $(2)))stage_$(1)_%.o,, $(2))
stage_1_object_files := $(call filter_out_stage,2,$(object_files))
stage_2_object_files := $(call filter_out_stage,1,$(object_files))
stage_1_debug_object_files := $(call filter_out_stage,2,$(debug_object_files))
stage_2_debug_object_files := $(call filter_out_stage,1,$(debug_object_files))

solution_1 := $(apps_dir)/stage_1_solution
solution_2 := $(apps_dir)/stage_2_solution
debug_solution_1 := $(debug_dir)/stage_1_solution
debug_solution_2 := $(debug_dir)/stage_2_solution

solution_files := $(solution_1) $(solution_2)
debug_files := $(debug_solution_1) $(debug_solution_2)

solutions: $(solution_files) .depend

solution_1: $(solution_1)
$(solution_1): $(stage_1_object_files)
	@ mkdir -p $(apps_dir)
	$(CC) $(CFLAGS) $(stage_1_object_files) -o $@

solution_2: $(solution_2)
$(solution_2): $(stage_2_object_files)
	@ mkdir -p $(apps_dir)
	$(CC) $(CFLAGS) $(stage_2_object_files) -o $@

$(build_dir)/%.o: $(source_dir)/%.c
	@ mkdir -p $(build_dir)
	$(CC) $(CFLAGS) -c $< -o $@

debug: $(debug_files) .depend

debug_solution_1: $(debug_solution_1)
$(debug_solution_1): $(stage_1_debug_object_files)
	@ mkdir -p $(debug_dir)
	$(CC) $(DEBUGFLAGS) $(stage_1_debug_object_files) -o $@

debug_solution_2: $(debug_solution_2)
$(debug_solution_2): $(stage_2_debug_object_files)
	@ mkdir -p $(debug_dir)
	$(CC) $(DEBUGFLAGS) $(stage_2_debug_object_files) -o $@

$(debug_build_dir)/%.o: $(source_dir)/%.c
	@ mkdir -p $(debug_build_dir)
	$(CC) $(DEBUGFLAGS) -c $< -o $@

.depend: $(source_files)
	rm -f "$@"
	$(CC) $(CFLAGS) -MM $^ -MF "$@"

include .depend

.PHONY: clean
clean:
	rm -fdr build
	rm -fdr build-debug
	rm -fdr debug
	rm -fdr apps
	rm -f .depend
