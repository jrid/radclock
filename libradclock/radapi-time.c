/*
 * Copyright (C) 2006-2011 Julien Ridoux <julien@synclab.org>
 *
 * This file is part of the radclock program.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */


#include "../config.h"

#include <sys/types.h>
#include <sys/time.h>

#include "radclock.h"
#include "radclock-private.h"
#include "logger.h"


// TODO: check all return values and error codes

// TODO: in all this file, check which functions need to call get_global_data and conditions for that (last update too far in the past ?)
// Should check for clock not synchronised? This is specific to the sync algo
// and should be designed that way. Following is a reminder of outdated code
/*
if ( ts < data->last_changed || ts - data->last_changed * data->phat > 10000 )
{
	logger(RADLOG_WARNING, 
		"radclock seems unsynchronised, last updated %7.1lf [sec] ago",
		(ts - data->last_changed) * data->phat);
}
*/




/*
 * Build the time using the absolute clock plus the local relative rate
 * correction (has no effect if not running plocal).
 */
static inline int
ffcounter_to_abstime_shm(const struct radclock *clock, vcounter_t vcount,
		long double *time)
{
	struct radclock_shm *shm;
	vcounter_t valid, last;
	double phat;
	int generation;

	shm = (struct radclock_shm *) clock->ipc_shm;
	do {
		/* Quality ingredients */
		generation = shm->gen;
		valid = SHM_DATA(shm)->valid_till;
		last  = SHM_DATA(shm)->last_changed;
		phat  = SHM_DATA(shm)->phat;

		*time = vcount * (long double)phat + SHM_DATA(shm)->ca;

		if ((clock->local_period_mode == RADCLOCK_LOCAL_PERIOD_ON)
			&& ((SHM_DATA(shm)->status & STARAD_WARMUP) != STARAD_WARMUP))
		{
			*time += (vcount - last) *
				(long double)(SHM_DATA(shm)->phat_local - phat);
		}
	} while (generation != shm->gen || !shm->gen);

	return raddata_quality(vcount, last, valid, phat);
}


/*
 * Build a delay using the difference clock.
 * This function does not fail, SKM model should be checked before call
 */
static inline int
ffcounter_to_difftime_shm(struct radclock *clock, vcounter_t from_vcount,
		vcounter_t till_vcount, long double *time)
{
	struct radclock_shm *shm;
	vcounter_t now, valid, last;
	double phat;
	int generation;

	// TODO Stupid performance penalty, but needs more thought
	if (radclock_get_vcounter(clock, &now))
		return (1);

	shm = (struct radclock_shm *) clock->ipc_shm;
	do {
		generation = shm->gen;
		valid = SHM_DATA(shm)->valid_till;
		last  = SHM_DATA(shm)->last_changed;
		phat  = SHM_DATA(shm)->phat;
		*time = (till_vcount - from_vcount) *
				(long double)SHM_DATA(shm)->phat_local;
	} while (generation != shm->gen || !shm->gen);

	return raddata_quality(now, last, valid, phat);
}


/*
 * Check if we are in the SKM model bounds or not
 * Need to know if we are in SKM world. If not, can't use the difference clock,
 * need to substract two absolute timestamps. Testing should always be done
 * using the 'current' vcount value since we use the current global data !!!
 * Use phat for this comparison but using plocal should be fine as well
 */
// XXX  quite a few issues here
// 		- the value of the SKM scale is hard coded ... but otherwise?
// 		- Validity of the global data
// 		- error code(s) to return
static inline int
in_skm(struct radclock *clock, const vcounter_t *past_count, const vcounter_t *vc)
{
	struct radclock_shm *shm;
	vcounter_t now;

	if (!vc)
		radclock_get_vcounter(clock, &now);
	now = *vc;

	shm = (struct radclock_shm *) clock->ipc_shm;
	if ((now - *past_count) * SHM_DATA(shm)->phat < 1024)
		return (1);
	else
		return (0);
}


int
radclock_gettime(struct radclock *clock, long double *abstime)
{
	vcounter_t vcount;
	int quality;

	/* Check for critical bad input */
	if (!clock || !abstime)
		return (1);

	/* Make sure we can get a raw timestamp */
	if (radclock_get_vcounter(clock, &vcount) < 0)
		return (1);
	
	/* Retrieve clock data */
	if (!clock->ipc_shm)
		return (1);

	quality = ffcounter_to_abstime_shm(clock, vcount, abstime);
	return (quality);
}


int
radclock_vcount_to_abstime(struct radclock *clock, const vcounter_t *vcount,
		long double *abstime)
{
	int quality;

	/* Check for critical bad input */
	if (!clock || !vcount || !abstime)
		return (1);

	if (!clock->ipc_shm)
		return (1);

	quality = ffcounter_to_abstime_shm(clock, *vcount, abstime);
	return (quality);
}


int
radclock_elapsed(struct radclock *clock, const vcounter_t *from_vcount,
		long double *duration)
{
	vcounter_t vcount;
	int quality = 0;

	/* Check for critical bad input */
	if (!clock || !from_vcount || !duration)
		return (1);

	/* Make sure we can get a raw timestamp */
	if (radclock_get_vcounter(clock, &vcount) < 0)
		return (1);
	
	/* Retrieve clock data */
	if (!clock->ipc_shm)
		return (1);

	quality = ffcounter_to_difftime_shm(clock, *from_vcount, vcount, duration);

// TODO is this the  good behaviour, we should request the clock data associated
// to from_vcount? maybe not
	if (!in_skm(clock, from_vcount, &vcount))
		return (1);

	return (quality);
}


int
radclock_duration(struct radclock *clock, const vcounter_t *from_vcount,
		const vcounter_t *till_vcount, long double *duration)
{
	vcounter_t vcount;
	int quality = 0;

	/* Check for critical bad input */
	if (!clock || !from_vcount || !till_vcount || !duration)
		return (1);

	/* Make sure we can get a raw timestamp */
	if (radclock_get_vcounter(clock, &vcount) < 0)
		return (1);
	
	/* Retrieve clock data */
	if (!clock->ipc_shm)
		return (1);

	quality = ffcounter_to_difftime_shm(clock, *from_vcount, *till_vcount, duration);

// TODO is this the  good behaviour, we should request the clock data associated
// to from_vcount? maybe not
	if (!in_skm(clock, from_vcount, &vcount))
		return (1);

	return (quality);
}

