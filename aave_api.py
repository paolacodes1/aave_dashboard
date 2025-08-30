import requests
import logging
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AaveAPIClient:
    """
    API client for fetching Aave protocol data from expand.network API
    Supports Polygon network for Aave V3 data
    """
    
    def __init__(self):
        self.base_url = "https://api.expand.network"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.timeout = 30
    
    def get_user_account_data(self, wallet_address: str) -> Optional[Dict]:
        """
        Get user account data including health factor, borrow amounts, etc.
        
        Args:
            wallet_address: Ethereum wallet address
            
        Returns:
            Dict with user account data or None if error
        """
        try:
            url = f"{self.base_url}/getuseraccountdata"
            params = {
                'userAddress': wallet_address,
                'network': 'polygon'  # Polygon network for Aave V3
            }
            
            logger.info(f"Fetching account data for {wallet_address[:10]}...")
            response = requests.get(url, params=params, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"Successfully fetched account data for {wallet_address[:10]}...")
            return data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed for {wallet_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting account data for {wallet_address}: {e}")
            return None
    
    def get_user_positions(self, wallet_address: str) -> Optional[Dict]:
        """
        Get detailed user lending and borrowing positions
        
        Args:
            wallet_address: Ethereum wallet address
            
        Returns:
            Dict with user positions or None if error
        """
        try:
            url = f"{self.base_url}/getuserpositions"
            params = {
                'userAddress': wallet_address,
                'network': 'polygon'
            }
            
            logger.info(f"Fetching positions for {wallet_address[:10]}...")
            response = requests.get(url, params=params, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"Successfully fetched positions for {wallet_address[:10]}...")
            return data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed for {wallet_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting positions for {wallet_address}: {e}")
            return None
    
    def format_health_factor(self, account_data: Dict) -> str:
        """
        Extract and format health factor from account data
        
        Args:
            account_data: Response from get_user_account_data
            
        Returns:
            Formatted health factor string
        """
        try:
            if not account_data or 'healthFactor' not in account_data:
                return "N/A"
            
            health_factor = account_data['healthFactor']
            if isinstance(health_factor, (int, float)):
                return f"{health_factor:.3f}"
            elif isinstance(health_factor, str):
                try:
                    return f"{float(health_factor):.3f}"
                except ValueError:
                    return health_factor
            else:
                return "N/A"
                
        except Exception as e:
            logger.error(f"Error formatting health factor: {e}")
            return "N/A"
    
    def format_borrowed_amount(self, account_data: Dict) -> str:
        """
        Extract and format total borrowed amount
        
        Args:
            account_data: Response from get_user_account_data
            
        Returns:
            Formatted borrowed amount string
        """
        try:
            if not account_data:
                return "N/A"
            
            # Look for various possible field names for borrowed amount
            borrowed_fields = ['totalDebtETH', 'totalBorrowed', 'borrowedAmount', 'totalDebt']
            
            for field in borrowed_fields:
                if field in account_data:
                    amount = account_data[field]
                    if isinstance(amount, (int, float)):
                        return f"${amount:,.2f}"
                    elif isinstance(amount, str):
                        try:
                            return f"${float(amount):,.2f}"
                        except ValueError:
                            continue
            
            return "N/A"
            
        except Exception as e:
            logger.error(f"Error formatting borrowed amount: {e}")
            return "N/A"
    
    def format_available_to_borrow(self, account_data: Dict) -> str:
        """
        Extract and format available borrowing capacity
        
        Args:
            account_data: Response from get_user_account_data
            
        Returns:
            Formatted available to borrow string
        """
        try:
            if not account_data:
                return "N/A"
            
            # Look for various possible field names
            available_fields = ['availableBorrowsETH', 'availableToBorrow', 'borrowingPower']
            
            for field in available_fields:
                if field in account_data:
                    amount = account_data[field]
                    if isinstance(amount, (int, float)):
                        return f"${amount:,.2f}"
                    elif isinstance(amount, str):
                        try:
                            return f"${float(amount):,.2f}"
                        except ValueError:
                            continue
            
            return "N/A"
            
        except Exception as e:
            logger.error(f"Error formatting available to borrow: {e}")
            return "N/A"
    
    def format_supplied_value(self, account_data: Dict) -> str:
        """
        Extract and format total supplied/collateral value
        
        Args:
            account_data: Response from get_user_account_data
            
        Returns:
            Formatted supplied value string
        """
        try:
            if not account_data:
                return "N/A"
            
            # Look for various possible field names
            supplied_fields = ['totalCollateralETH', 'totalSupplied', 'collateralValue', 'suppliedAmount']
            
            for field in supplied_fields:
                if field in account_data:
                    amount = account_data[field]
                    if isinstance(amount, (int, float)):
                        return f"${amount:,.2f}"
                    elif isinstance(amount, str):
                        try:
                            return f"${float(amount):,.2f}"
                        except ValueError:
                            continue
            
            return "N/A"
            
        except Exception as e:
            logger.error(f"Error formatting supplied value: {e}")
            return "N/A"
    
    def format_net_worth(self, account_data: Dict) -> str:
        """
        Calculate and format net worth (supplied - borrowed)
        
        Args:
            account_data: Response from get_user_account_data
            
        Returns:
            Formatted net worth string
        """
        try:
            if not account_data:
                return "N/A"
            
            # Try to extract supplied and borrowed amounts
            supplied_fields = ['totalCollateralETH', 'totalSupplied', 'collateralValue']
            borrowed_fields = ['totalDebtETH', 'totalBorrowed', 'borrowedAmount']
            
            supplied_amount = None
            borrowed_amount = None
            
            # Find supplied amount
            for field in supplied_fields:
                if field in account_data:
                    try:
                        supplied_amount = float(account_data[field])
                        break
                    except (ValueError, TypeError):
                        continue
            
            # Find borrowed amount
            for field in borrowed_fields:
                if field in account_data:
                    try:
                        borrowed_amount = float(account_data[field])
                        break
                    except (ValueError, TypeError):
                        continue
            
            # Calculate net worth
            if supplied_amount is not None and borrowed_amount is not None:
                net_worth = supplied_amount - borrowed_amount
                return f"${net_worth:,.2f}"
            
            return "N/A"
            
        except Exception as e:
            logger.error(f"Error calculating net worth: {e}")
            return "N/A"
    
    def get_wallet_data(self, wallet_address: str) -> Dict[str, str]:
        """
        Get all wallet data in the format expected by the GUI
        
        Args:
            wallet_address: Ethereum wallet address
            
        Returns:
            Dict with all formatted wallet metrics
        """
        try:
            # Get account data from API
            account_data = self.get_user_account_data(wallet_address)
            
            if not account_data:
                return {
                    'health_factor': 'API Error',
                    'total_borrowed': 'API Error',
                    'available_to_borrow': 'API Error',
                    'supplied_value': 'API Error',
                    'net_worth': 'API Error'
                }
            
            # Format all the data
            return {
                'health_factor': self.format_health_factor(account_data),
                'total_borrowed': self.format_borrowed_amount(account_data),
                'available_to_borrow': self.format_available_to_borrow(account_data),
                'supplied_value': self.format_supplied_value(account_data),
                'net_worth': self.format_net_worth(account_data)
            }
            
        except Exception as e:
            logger.error(f"Error getting wallet data for {wallet_address}: {e}")
            return {
                'health_factor': 'Error',
                'total_borrowed': 'Error',
                'available_to_borrow': 'Error',
                'supplied_value': 'Error',
                'net_worth': 'Error'
            }

# Create a global instance for easy importing
aave_api = AaveAPIClient()