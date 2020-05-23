using QIQI.EProjectFile;
using QIQI.EProjectFile.Statements;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace InjectedEComRepair
{
    public static class EProjectRepair
    {
        public static void RepairEProjectFile(Stream source, Stream target, ProjectFileReader.OnInputPassword inputPassword = null, int engine = 0)
        {
            var file = new EProjectFile();
            file.Load(source, inputPassword);
            var libNameMap = new IdToNameMap(file.Code.Libraries);
            var classIdMap = file.Code.Classes.ToDictionary(x => x.Id);
            var methodIdMap = file.Code.Methods.ToDictionary(x => x.Id);
            file.ESystemInfo.FileType = 1;
            foreach (var classInfo in file.Code.Classes)
            {
                if (!ValidEplName(classInfo.Name))
                {
                    classInfo.Name = ParseDebugComment(classInfo.Comment);
                    if (classInfo.Name == null)
                    {
                        if (classInfo.Comment == "_-@M<>")
                        {
                            classInfo.Comment = "";
                        }
                        classInfo.Name = (classInfo.BaseClass == 0 ? "_程序集" : "_类") + (classInfo.Id & EplSystemId.Mask_Num).ToString("X");
                    }
                    else
                    {
                        classInfo.Comment = "";
                    }
                }
                FixVariablesName(classInfo.Variables, classInfo.BaseClass == 0 ? "_程序集变量" : "_成员");
            }
            FixVariablesName(file.Code.GlobalVariables, "_全局");
            foreach (var method in file.Code.Methods)
            {
                if (!ValidEplName(method.Name))
                {
                    method.Name = ParseDebugComment(method.Comment);
                    if (method.Name == null)
                    {
                        if (method.Comment == "_-@S<>")
                        {
                            method.Comment = "";
                        }
                        method.Name = $"_子程序{(method.Id & EplSystemId.Mask_Num).ToString("X")}";
                    }
                    else
                    {
                        method.Comment = "";
                    }
                }
                FixVariablesName(method.Parameters, "_参数", true);
                FixVariablesName(method.Variables, "_局部", true);

                StatementBlock block = null;
                try
                {
                    var codeData = method.CodeData;
#pragma warning disable CS0612 // 类型或成员已过时
                    block = CodeDataParser.ParseStatementBlock(method.CodeData.ExpressionData, file.Encoding, out codeData.LineOffest, out codeData.BlockOffest);
#pragma warning restore CS0612 // 类型或成员已过时
                    if (engine == 1)
                    {
                        codeData = block.ToCodeData(file.Encoding);
                    }
                    method.CodeData = codeData;
                }
                catch (Exception exception)
                {
                    method.Comment = $"[**修复失败:{exception.ToString().Replace("\r\n", "<NewLine>")}**]{method.Comment}";
                    continue;
                }
            }
            foreach (var structInfo in file.Code.Structs)
            {
                if (!ValidEplName(structInfo.Name))
                {
                    structInfo.Name = $"_结构{(structInfo.Id & EplSystemId.Mask_Num).ToString("X")}";
                }
                FixVariablesName(structInfo.Member, "_成员", false);
            }
            foreach (var dll in file.Code.DllDeclares)
            {
                if (!ValidEplName(dll.Name))
                {
                    dll.Name = dll.EntryPoint;
                    if (dll.Name.StartsWith("@"))
                    {
                        dll.Name = dll.Name.Substring(1);
                    }
                    dll.Name = "_" + dll.Name;
                    if (!ValidEplName("_" + dll.Name))
                    {
                        dll.Name = "";
                    }
                    dll.Name = $"_DLL命令{(dll.Id & EplSystemId.Mask_Num).ToString("X")}{dll.Name}";
                }
                FixVariablesName(dll.Parameters, "_参数", true);
            }
            foreach (var constant in file.Resource.Constants)
            {
                if (!ValidEplName(constant.Name))
                {
                    constant.Name = constant.Value == null ? "" : $"_常量{(constant.Id & EplSystemId.Mask_Num).ToString("X")}";
                }
            }
            foreach (var formInfo in file.Resource.Forms)
            {
                if (!ValidEplName(formInfo.Name))
                {
                    formInfo.Name = $"_窗口{(formInfo.Id & EplSystemId.Mask_Num).ToString("X")}";
                }
                foreach (var elem in formInfo.Elements)
                {
                    if (elem is FormMenuInfo menu)
                    {
                        MethodInfo eventMethod = null;
                        if (menu.ClickEvent != 0)
                        {
                            methodIdMap.TryGetValue(menu.ClickEvent, out eventMethod);
                        }
                        if (string.IsNullOrEmpty(menu.Name))
                        {
                            if (ValidEplName("_" + menu.Text))
                            {
                                menu.Name = $"_菜单{(menu.Id & EplSystemId.Mask_Num).ToString("X")}_{menu.Text}";
                            }
                            else
                            {
                                menu.Name = $"_菜单{(menu.Id & EplSystemId.Mask_Num).ToString("X")}";
                            }
                            if (eventMethod != null && eventMethod.Name != null && eventMethod.Name.StartsWith("_") && eventMethod.Name.EndsWith("_被选择"))//尝试从事件子程序名还原名称
                            {
                                menu.Name = eventMethod.Name.Substring(1, eventMethod.Name.Length - 5);
                            }
                        }
                        if (eventMethod != null)
                        {
                            eventMethod.Name = $"_{menu.Name}_被选择";
                        }
                    }
                    else if (elem is FormControlInfo control)
                    {
                        var elemName = control.Name;

                        if (!ValidEplName(elemName))
                        {
                            if (control.Events.Length > 0)//尝试从子程序名恢复窗口名
                            {
                                var eventItem = control.Events[0];
                                if (methodIdMap.TryGetValue(eventItem.Value, out var eventMethod))
                                {
                                    var eventName = libNameMap.GetLibTypeName(control.DataType, eventItem.Key);
                                    if (eventMethod.Name.StartsWith("_") && eventMethod.Name.EndsWith($"_{eventName}"))
                                    {
                                        formInfo.Name = eventMethod.Name.Substring(1, eventMethod.Name.Length - 1 - eventName.Length - 1);
                                    }
                                }
                            }
                            elemName = formInfo.Name;
                        }
                        foreach (var eventItem in control.Events)
                        {
                            if (methodIdMap.TryGetValue(eventItem.Value, out var eventMethod))
                            {
                                var eventName = libNameMap.GetLibTypeName(control.DataType, eventItem.Key);
                                eventMethod.Name = $"_{elemName}_{eventName}";
                            }
                        }
                    }
                }
                if (classIdMap.TryGetValue(formInfo.Class, out var formClass))
                {
                    var prefix = $"[“{formInfo.Name}”的窗口程序集]";
                    if (!formClass.Comment.StartsWith(prefix))
                    {
                        formClass.Comment = $"{prefix}{formClass.Comment}";
                    }
                }
            }
            {
                var newInitMethod = new List<int>(file.InitEcSectionInfo.InitMethod.Length);
                var newEcName = new List<string>(file.InitEcSectionInfo.InitMethod.Length);
                for (int i = 0; i < file.InitEcSectionInfo.InitMethod.Length; i++)
                {
                    if (!methodIdMap.TryGetValue(file.InitEcSectionInfo.InitMethod[i], out var initMethod))
                    {
                        continue;
                    }
                    initMethod.Name = $"初始模块_{i + 1}";
                    if (ValidEplName("_" + file.InitEcSectionInfo.EcName[i]))
                    {
                        initMethod.Name += "_" + file.InitEcSectionInfo.EcName[i];
                    }

                    var prefix = $"[禁止删除][注意：本子程序将自动在启动时被调用，且早于 _启动子程序 被调用][为内联的模块“{file.InitEcSectionInfo.EcName[i]}”做初始化工作]";
                    if (!initMethod.Comment.StartsWith(prefix))
                    {
                        initMethod.Comment = $"{prefix}{initMethod.Comment}";
                    }

                    newInitMethod.Add(file.InitEcSectionInfo.InitMethod[i]);
                    newEcName.Add(i < file.InitEcSectionInfo.EcName.Length ? file.InitEcSectionInfo.EcName[i] : "");
                }
                file.InitEcSectionInfo.InitMethod = newInitMethod.ToArray();
                file.InitEcSectionInfo.EcName = newEcName.ToArray();
            }
            {
                if (methodIdMap.TryGetValue(file.Code.MainMethod, out var mainMethod))
                {
                    mainMethod.Name = "_启动子程序";
                    if (file.InitEcSectionInfo.InitMethod.Length > 0)
                    {
                        var prefix = "[注意：本子程序将在 初始模块_X 后调用]";
                        if (!mainMethod.Comment.StartsWith(prefix))
                        {
                            mainMethod.Comment = $"{prefix}{mainMethod.Comment}";
                        }
                    }
                }
            }
            file.Save(target);
        }
        private static void FixVariablesName(AbstractVariableInfo[] variables, string prefix, bool useIndexInsteadOfId = false)
        {
            int i = 1;
            foreach (var variable in variables)
            {
                if (string.IsNullOrEmpty(variable.Name))
                {
                    variable.Name = prefix + (useIndexInsteadOfId ? i.ToString() : (variable.Id & EplSystemId.Mask_Num).ToString("X"));
                }
                i++;
            }
        }

        private static Regex validEplNameRegex = new Regex(@"^[_A-Za-z\u0080-\uFFFF][_0-9A-Za-z\u0080-\uFFFF]*$", RegexOptions.Compiled);
        private static bool ValidEplName(string name)
        {
            return validEplNameRegex.IsMatch(name);
        }
        private static Regex debugCommentMatchRegex = new Regex(@"^_-@[MS]<([_A-Za-z\u0080-\uFFFF][_0-9A-Za-z\u0080-\uFFFF]*)>$", RegexOptions.Compiled);
        private static string ParseDebugComment(string comment)
        {
            var matchItem = debugCommentMatchRegex.Match(comment);
            if (matchItem == null || !matchItem.Success)
            {
                return null;
            }
            return matchItem.Groups[1].Value;
        }

    }
}
