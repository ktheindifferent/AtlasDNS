import { createSlice, PayloadAction } from '@reduxjs/toolkit';

interface AuthState {
  token: string | null;
  user: {
    id: string;
    username: string;
    email: string;
    role: string;
  } | null;
  isAuthenticated: boolean;
}

const initialState: AuthState = {
  token: localStorage.getItem('token'),
  user: null,
  isAuthenticated: false,
};

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    loginSuccess: (state, action: PayloadAction<{ token: string; user: AuthState['user'] }>) => {
      state.token = action.payload.token;
      state.user = action.payload.user;
      state.isAuthenticated = true;
      localStorage.setItem('token', action.payload.token);
    },
    logout: (state) => {
      state.token = null;
      state.user = null;
      state.isAuthenticated = false;
      localStorage.removeItem('token');
    },
    updateUser: (state, action: PayloadAction<AuthState['user']>) => {
      state.user = action.payload;
    },
  },
});

export const { loginSuccess, logout, updateUser } = authSlice.actions;
export default authSlice.reducer;