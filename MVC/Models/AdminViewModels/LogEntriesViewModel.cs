using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;

namespace MVC.Models.AdminViewModels
{
    public class LogEntriesViewModel
    {
        public LogEntriesViewModel()
        {
        }
        public int TZoffset { get; set; }
        public int TotalPages { get; set; }
        public int PageIndex {  get; set; }
        public int RowIndex { get; set; }
        public string StartDate { get; set; }
        public string EndDate { get; set; }
        public string Country { get; set; }
        public LogType Type { get; set; }
        public List<SelectListItem> Types { get; set; }
        public List<LogEntry> Entries { get; set; }
        public int EntryCount { get; set; }

        public bool HasPreviousPage
        {
            get
            {
                return (PageIndex > 1);
            }
        }
        public bool HasNextPage
        {
            get
            {
                return (PageIndex < TotalPages);
            }
        }
    }
}
