#!/usr/bin/env python3
"""
IndexedDB Scraper - A tool to extract data from a website's IndexedDB storage
using the Playwright library.

This script navigates to a specified URL, extracts all databases,
then retrieves all object stores and their key-value pairs.
"""

import asyncio
import json
import argparse
from typing import Dict, List, Any, Optional
from playwright.async_api import async_playwright, Page, Browser


class IndexedDBScraper:
    """Extract IndexedDB data from websites using Playwright."""

    def __init__(self, headless: bool = True, timeout: int = 30000):
        """Initialize the IndexedDB scraper.
        
        Args:
            headless: Whether to run the browser in headless mode
            timeout: Maximum time in ms to wait for page operations
        """
        self.headless = headless
        self.timeout = timeout
        self.browser = None
        self.page = None

    async def __aenter__(self):
        """Set up the browser and page when used as context manager."""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=self.headless)
        self.page = await self.browser.new_page()
        self.page.set_default_timeout(self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up resources when exiting context manager."""
        if self.browser:
            await self.browser.close()

    async def navigate(self, url: str) -> None:
        """Navigate to the target URL.
        
        Args:
            url: The URL to navigate to
        """
        try:
            await self.page.goto(url, wait_until="networkidle")
            print(f"✅ Successfully navigated to {url}")
        except Exception as e:
            print(f"❌ Failed to navigate to {url}: {str(e)}")
            raise

    async def get_database_names(self) -> List[str]:
        """Get all IndexedDB database names from the page.
        
        Returns:
            List of database names
        """
        return await self.page.evaluate("""() => {
            return new Promise((resolve, reject) => {
                const databases = indexedDB.databases ? 
                    indexedDB.databases() : 
                    Promise.reject("indexedDB.databases() not supported");
                
                databases
                    .then(dbs => resolve(dbs.map(db => db.name)))
                    .catch(err => {
                        console.error("Error getting database names:", err);
                        // Fallback for browsers not supporting indexedDB.databases()
                        resolve([]);
                    });
            });
        }""")

    async def get_object_store_names(self, db_name: str) -> List[str]:
        """Get all object store names for a specific database.
        
        Args:
            db_name: Name of the database
            
        Returns:
            List of object store names
        """
        return await self.page.evaluate("""(dbName) => {
            return new Promise((resolve, reject) => {
                const request = indexedDB.open(dbName);
                
                request.onerror = event => {
                    console.error(`Error opening database ${dbName}:`, event);
                    reject(new Error(`Could not open database: ${event.target.error}`));
                };
                
                request.onsuccess = event => {
                    const db = event.target.result;
                            valueRequest.onerror = event => {
                                console.error(`Error getting values from ${storeName}:`, event);
                                db.close();
                                reject(new Error(`Could not get values: ${event.target.error}`));
                            };

                        };
                        
                        keyRequest.onerror = event => {

                            console.error(`Error getting keys from ${storeName}:`, event);

                            db.close();

                            reject(new Error(`Could not get keys: ${event.target.error}`));

                        };

                        
                    } catch (e) {
                        db.close();

                        reject(new Error(`Error accessing object store ${storeName}: ${e.message}`));

                    }

                };
            });

        }""", [db_name, store_name])


    async def scrape_all_data(self) -> Dict[str, Dict[str, Dict[str, Any]]]:

        """Scrape all IndexedDB data from the current page.
        

        Returns:

            Nested dictionary of all database data:
            {database_name: {object_store_name: {key: value}}}

        """

        result = {}
        

        try:
            # Get all database names
            db_names = await self.get_database_names()
            if not db_names:

                print("⚠️ No IndexedDB databases found or browser doesn't support indexedDB.databases()")
                return result
                
            print(f"📊 Found {len(db_names)} database(s): {', '.join(db_names)}")
            
            # Process each database
            for db_name in db_names:
                result[db_name] = {}
                
                try:
                    # Get object store names for this database
                    store_names = await self.get_object_store_names(db_name)
                    print(f"  📁 Database '{db_name}' has {len(store_names)} object store(s): {', '.join(store_names)}")
                    
                    # Process each object store
                    for store_name in store_names:
                        try:
                            # Get all data from this object store
                            store_data = await self.get_object_store_data(db_name, store_name)
                            print(f"    🔑 Object store '{store_name}' has {len(store_data)} key-value pair(s)")
                            result[db_name][store_name] = store_data
                        except Exception as e:
                            print(f"    ❌ Error getting data from object store '{store_name}': {str(e)}")
                            result[db_name][store_name] = {"error": str(e)}
                            
                except Exception as e:
                    print(f"  ❌ Error processing database '{db_name}': {str(e)}")
                    result[db_name] = {"error": str(e)}
                    
        except Exception as e:
            print(f"❌ Error during data scraping: {str(e)}")
            
        return result

    async def export_to_json(self, data: Dict[str, Any], output_file: str) -> None:
        """Export the data to a JSON file.
        
        Args:
            data: The data to export
            output_file: Path to the output file
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            print(f"✅ Data successfully exported to {output_file}")
        except Exception as e:
            print(f"❌ Failed to export data: {str(e)}")


async def main(url: str, output_file: str = "indexeddb_data.json", headless: bool = True):
    """Main function to run the IndexedDB scraper.
    
    Args:
        url: The URL to scrape IndexedDB data from
        output_file: Path to the output file
        headless: Whether to run the browser in headless mode
    """
    async with IndexedDBScraper(headless=headless) as scraper:
        try:
            # Navigate to the URL
            await scraper.navigate(url)
            
            # Wait for IndexedDB to be fully initialized
            await scraper.page.wait_for_timeout(2000)
            
            # Extract all IndexedDB data
            print("🔍 Starting IndexedDB data extraction...")
            all_data = await scraper.scrape_all_data()
            
            # Export the data to a JSON file
            await scraper.export_to_json(all_data, output_file)

            
            print(f"✅ IndexedDB scraping completed for {url}")

            

        except Exception as e:
            print(f"❌ Failed to scrape IndexedDB data: {str(e)}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape IndexedDB data from a website")

    parser.add_argument("url", help="URL of the website to scrape")
    parser.add_argument("-o", "--output", default="indexeddb_data.json", 

                        help="Output JSON file (default: indexeddb_data.json)")
    parser.add_argument("--visible", action="store_true", 

                        help="Run in visible mode (not headless)")

    

    args = parser.parse_args()

    

    asyncio.run(main(args.url, args.output, not args.visible))
