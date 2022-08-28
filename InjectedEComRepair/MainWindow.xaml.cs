using QIQI.EProjectFile;
using QIQI.EProjectFile.Sections;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace InjectedEComRepair
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            this.OutputTextBox.Text = Properties.Resources.WelcomeText;
            var guiVersionInfo = Attribute.GetCustomAttribute(typeof(MainWindow).Assembly, typeof(System.Reflection.AssemblyInformationalVersionAttribute))
                as System.Reflection.AssemblyInformationalVersionAttribute;
            var coreVersionInfo = Attribute.GetCustomAttribute(typeof(EplDocument).Assembly, typeof(System.Reflection.AssemblyInformationalVersionAttribute))
                as System.Reflection.AssemblyInformationalVersionAttribute;
            this.Title = string.Format("易模块手工分析型病毒查杀工具 v{0} (Core: v{1})", guiVersionInfo?.InformationalVersion ?? "Unknown", coreVersionInfo?.InformationalVersion ?? "Unknown");
        }

        private void SelectFileButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog()
            {
                Filter = "EPL files|*.e;*.ec|All files|*"
            };
            if (dialog.ShowDialog().GetValueOrDefault())
            {
                InputFileTextBox.Text = dialog.FileName;
            }
        }

        private void DebugButton_Click(object sender, RoutedEventArgs e)
        {
            bool outputSectionData = OutputSectionDataCheckBox.IsChecked.GetValueOrDefault();
            bool parseCodeData = ParseCodeDataCheckBox.IsChecked.GetValueOrDefault();
            bool outputTextCode = OutputTextCodeCheckBox.IsChecked.GetValueOrDefault();
            string fileName = InputFileTextBox.Text;
            OutputTextBox.Text = "正在处理...";

            new Task(() =>
            {
                try
                {
                    var doc = new EplDocument();
                    var output = new StringBuilder();
                    doc.Load(File.OpenRead(fileName), InputPassword);
                    var encoding = doc.DetermineEncoding();
                    var codeSection = doc.Get(CodeSection.Key);
                    var resourceSection = doc.Get(ResourceSection.Key);
                    if (outputSectionData)
                    {
                        output.AppendLine(JsonSerializer.Serialize(doc.Sections, new JsonSerializerOptions()
                        {
                            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                            WriteIndented = true
                        }));
                    }
                    if (parseCodeData)
                    {
                        output.AppendLine("<<<<<<<<<<<<<<<ParseTest>>>>>>>>>>>>>>>");
                        foreach (var method in codeSection.Methods)
                        {
                            output.AppendLine($"###Method: {(string.IsNullOrEmpty(method.Name) ? "Unknown" : method.Name)}{$"Id: {method.Id})###"}");
                            try
                            {
#pragma warning disable CS0612 // 类型或成员已过时
                                var block = CodeDataParser.ParseStatementBlock(method.CodeData.ExpressionData, encoding, out var lineOffest, out var blockOffest);
#pragma warning restore CS0612 // 类型或成员已过时
                                var GenCodeData = block.ToCodeData(encoding);
                                output.Append("Raw: ");
                                output.AppendLine(method.CodeData.ToString());
                                output.Append("FullRewrite: ");
                                output.AppendLine(GenCodeData.ToString());
                                output.Append("OldOffestRepairer: ");
                                output.AppendLine("{");
                                output.AppendLine("  \"LineOffest\": \"" + lineOffest.ToHexString() + "\"");
                                output.AppendLine("  \"BlockOffest\": \"" + blockOffest.ToHexString() + "\"");
                                output.AppendLine("}");
                            }
#pragma warning disable CA1031 // Do not catch general exception types
                            catch (Exception exception)
                            {
                                output.AppendLine("出现错误：");
                                output.AppendLine(exception.ToString());
                                output.AppendLine();
                            }
#pragma warning restore CA1031 // Do not catch general exception types
                        }
                    }
                    if (outputTextCode)
                    {
                        output.AppendLine("<<<<<<<<<<<<<<<TextCode>>>>>>>>>>>>>>>");
                        var nameMap = new IdToNameMap(doc);
                        output.AppendLine(".版本 2");
                        output.AppendLine();
                        output.AppendLine(codeSection.ToTextCode(nameMap));
                        output.AppendLine(resourceSection.ToTextCode(nameMap));
                    }
                    
                    Dispatcher.Invoke(new Action(() =>
                    {
                        OutputTextBox.Text = output.ToString();
                    }));
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception exception)
                {
                    Dispatcher.Invoke(new Action(() =>
                    {
                        OutputTextBox.Text = $"出现错误：\r\n{exception}\r\n请加群后将文件发送给作者以便修复此问题";
                    }));
                }
#pragma warning restore CA1031 // Do not catch general exception types
            })
            .Start();
        }

        private void RepairButton_Click(object sender, RoutedEventArgs e)
        {

            string fileName = InputFileTextBox.Text;
            string output = OutputFileTextBox.Text;
            int engine = FixOffestRadioButton.IsChecked.GetValueOrDefault() ? 0 : 1;
            OutputTextBox.Text = "正在处理...";
            new Task(() =>
            {
                try
                {
                    EProjectRepair.RepairEProjectFile(File.OpenRead(fileName), File.Create(output), InputPassword, engine);
                    Dispatcher.Invoke(new Action(() =>
                    {
                        OutputTextBox.Text = $"处理完成，修复后的文件：{output}";
                    }));
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception exception)
                {
                    Dispatcher.Invoke(new Action(() =>
                    {
                        OutputTextBox.Text = $"出现错误：\r\n{exception}\r\n请加群后将文件发送给作者以便修复此问题";
                    }));
                }
#pragma warning restore CA1031 // Do not catch general exception types

            }).Start();
        }

        private string InputPassword(string tips)
        {
            return Dispatcher.Invoke(new Func<string>(() =>
            {
                var dialog = new InputPasswordDialog(tips);
                if (dialog.ShowDialog().GetValueOrDefault())
                {
                    return dialog.Password;
                }
                return null;
            })).ToString();
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string fileName = ((Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();
                InputFileTextBox.Text = fileName;
            }
        }

        private void OutputTextBox_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Handled = true;
        }
    }
}
