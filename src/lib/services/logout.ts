import { goto } from '$app/navigation';
import { logout } from '../stores/login';
export async function logoutUser(redirectToHome = true) {
  logout();
  if (redirectToHome) await goto('/');
}
