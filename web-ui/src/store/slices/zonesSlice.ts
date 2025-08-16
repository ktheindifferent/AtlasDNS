import { createSlice, PayloadAction, createAsyncThunk } from '@reduxjs/toolkit';
import { zoneApi } from '../../services/api';

export interface Zone {
  id: string;
  name: string;
  type: 'master' | 'slave' | 'forward';
  status: 'active' | 'inactive' | 'error';
  records: number;
  dnssecEnabled: boolean;
  lastModified: string;
  serial: number;
  ttl: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
  primaryNs: string;
  adminEmail: string;
}

interface ZonesState {
  zones: Zone[];
  selectedZone: Zone | null;
  loading: boolean;
  error: string | null;
  totalCount: number;
  currentPage: number;
  pageSize: number;
}

const initialState: ZonesState = {
  zones: [],
  selectedZone: null,
  loading: false,
  error: null,
  totalCount: 0,
  currentPage: 1,
  pageSize: 10,
};

export const fetchZones = createAsyncThunk(
  'zones/fetchZones',
  async (params?: { page?: number; limit?: number; search?: string }) => {
    const response = await zoneApi.list(params);
    return response.data;
  }
);

export const fetchZone = createAsyncThunk(
  'zones/fetchZone',
  async (zoneId: string) => {
    const response = await zoneApi.get(zoneId);
    return response.data;
  }
);

export const createZone = createAsyncThunk(
  'zones/createZone',
  async (data: Partial<Zone>) => {
    const response = await zoneApi.create(data);
    return response.data;
  }
);

export const updateZone = createAsyncThunk(
  'zones/updateZone',
  async ({ zoneId, data }: { zoneId: string; data: Partial<Zone> }) => {
    const response = await zoneApi.update(zoneId, data);
    return response.data;
  }
);

export const deleteZone = createAsyncThunk(
  'zones/deleteZone',
  async (zoneId: string) => {
    await zoneApi.delete(zoneId);
    return zoneId;
  }
);

const zonesSlice = createSlice({
  name: 'zones',
  initialState,
  reducers: {
    setSelectedZone: (state, action: PayloadAction<Zone | null>) => {
      state.selectedZone = action.payload;
    },
    setCurrentPage: (state, action: PayloadAction<number>) => {
      state.currentPage = action.payload;
    },
    setPageSize: (state, action: PayloadAction<number>) => {
      state.pageSize = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchZones.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchZones.fulfilled, (state, action) => {
        state.loading = false;
        state.zones = action.payload.zones;
        state.totalCount = action.payload.total;
      })
      .addCase(fetchZones.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch zones';
      })
      .addCase(fetchZone.fulfilled, (state, action) => {
        state.selectedZone = action.payload;
      })
      .addCase(createZone.fulfilled, (state, action) => {
        state.zones.unshift(action.payload);
        state.totalCount++;
      })
      .addCase(updateZone.fulfilled, (state, action) => {
        const index = state.zones.findIndex(z => z.id === action.payload.id);
        if (index !== -1) {
          state.zones[index] = action.payload;
        }
        if (state.selectedZone?.id === action.payload.id) {
          state.selectedZone = action.payload;
        }
      })
      .addCase(deleteZone.fulfilled, (state, action) => {
        state.zones = state.zones.filter(z => z.id !== action.payload);
        state.totalCount--;
        if (state.selectedZone?.id === action.payload) {
          state.selectedZone = null;
        }
      });
  },
});

export const { setSelectedZone, setCurrentPage, setPageSize } = zonesSlice.actions;
export default zonesSlice.reducer;